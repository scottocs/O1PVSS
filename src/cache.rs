//! Bounded, process-local memoization of deterministic public preprocessing.
//! Never stores secret keys, nonces, ciphertexts, proof results, or decryption shares.
use ark_ff::{batch_inversion, PrimeField};
use ark_serialize::CanonicalSerialize;
use std::{
    any::{Any, TypeId},
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
};

const CAPACITY: usize = 32;
type Erased = Arc<dyn Any + Send + Sync>;
#[derive(Hash, PartialEq, Eq)]
struct Key {
    namespace: &'static str,
    value_type: TypeId,
    binding: Vec<u8>,
}
#[derive(Default)]
struct Cache {
    entries: HashMap<Key, (Erased, u64)>,
    clock: u64,
    hits: u64,
    misses: u64,
}
static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub struct PublicCacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
}
pub fn public_cache_stats() -> PublicCacheStats {
    let cache = CACHE.get_or_init(Default::default).lock().unwrap();
    PublicCacheStats {
        entries: cache.entries.len(),
        hits: cache.hits,
        misses: cache.misses,
    }
}

pub(crate) fn binding(value: &impl CanonicalSerialize) -> Vec<u8> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("serialize public cache context");
    bytes
}

pub(crate) fn get_or_try_insert<T: Any + Send + Sync>(
    namespace: &'static str,
    binding: Vec<u8>,
    build: impl FnOnce() -> Option<T>,
) -> Option<Arc<T>> {
    let key = Key {
        namespace,
        value_type: TypeId::of::<T>(),
        binding,
    };
    let mutex = CACHE.get_or_init(Default::default);
    {
        let mut cache = mutex.lock().unwrap();
        cache.clock += 1;
        let clock = cache.clock;
        if let Some((value, used)) = cache.entries.get_mut(&key) {
            *used = clock;
            let value = value.clone().downcast().ok()?;
            cache.hits += 1;
            return Some(value);
        }
        cache.misses += 1;
    }
    // Expensive public arithmetic does not hold the global lock.
    let value = Arc::new(build()?);
    let mut cache = mutex.lock().unwrap();
    if let Some((existing, _)) = cache.entries.get(&key) {
        return existing.clone().downcast().ok();
    }
    if cache.entries.len() >= CAPACITY {
        let oldest = cache
            .entries
            .iter()
            .min_by_key(|(_, (_, used))| *used)
            .map(|(key, _)| Key {
                namespace: key.namespace,
                value_type: key.value_type,
                binding: key.binding.clone(),
            });
        if let Some(oldest) = oldest {
            cache.entries.remove(&oldest);
        }
    }
    cache.clock += 1;
    let clock = cache.clock;
    cache.entries.insert(key, (value.clone(), clock));
    Some(value)
}

pub(crate) fn evaluation_points<F: PrimeField>(n: usize, offset: usize) -> Arc<Vec<F>> {
    get_or_try_insert(
        "evaluation-points",
        binding(&(n as u64, offset as u64)),
        || Some((offset..offset + n).map(|i| F::from(i as u64)).collect()),
    )
    .unwrap()
}

/// For immutable public setup elements only. Dynamic ciphertext/share checks
/// deliberately do not use this memoization.
pub(crate) fn valid_public_element<G: ark_ec::PrimeGroup>(point: &G) -> bool {
    // Compressed encodings are not injective on malformed curve inputs.
    // Include both affine coordinates before memoizing a membership check.
    let mut key = Vec::new();
    point
        .serialize_uncompressed(&mut key)
        .expect("serialize public element");
    get_or_try_insert("public-element-validation", key, || {
        Some((*point, point.check().is_ok()))
    })
    .unwrap()
    .1
}

pub(crate) fn barycentric_weights<F: PrimeField>(points: &[F]) -> Option<Arc<Vec<F>>> {
    let mut seen = HashSet::new();
    if points.is_empty() || points.iter().any(|x| !seen.insert(*x)) {
        return None;
    }
    get_or_try_insert("barycentric-weights", binding(&points.to_vec()), || {
        let mut denominators: Vec<F> = points
            .iter()
            .enumerate()
            .map(|(i, x)| {
                points
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .fold(F::from(1u64), |a, (_, y)| a * (*x - y))
            })
            .collect();
        batch_inversion(&mut denominators);
        Some(denominators)
    })
}

pub(crate) fn evaluation_powers<F: PrimeField>(
    points: &[F],
    coefficients: usize,
) -> Arc<Vec<Vec<F>>> {
    get_or_try_insert(
        "evaluation-powers",
        binding(&(points.to_vec(), coefficients as u64)),
        || {
            Some(
                points
                    .iter()
                    .map(|x| {
                        let mut power = F::from(1u64);
                        (0..coefficients)
                            .map(|_| {
                                let value = power;
                                power *= x;
                                value
                            })
                            .collect()
                    })
                    .collect(),
            )
        },
    )
    .unwrap()
}

/// Pure field data: sharing this across setups is safe precisely because the
/// exact evaluation points and target points, not just (n,t), form the key.
pub(crate) fn interpolation_weights<F: PrimeField>(
    points: &[F],
    targets: &[F],
) -> Option<Arc<Vec<Vec<F>>>> {
    if points.is_empty() || targets.is_empty() {
        return None;
    }
    let mut seen = HashSet::new();
    if points.iter().any(|x| !seen.insert(*x)) {
        return None;
    }
    get_or_try_insert(
        "interpolation-weights",
        binding(&(points.to_vec(), targets.to_vec())),
        || {
            let denominators = barycentric_weights(points)?;
            Some(
                targets
                    .iter()
                    .map(|at| {
                        if let Some(i) = points.iter().position(|x| x == at) {
                            let mut row = vec![F::from(0u64); points.len()];
                            row[i] = F::from(1u64);
                            return row;
                        }
                        let mut differences: Vec<_> = points.iter().map(|x| *at - x).collect();
                        let numerator = differences.iter().copied().product::<F>();
                        batch_inversion(&mut differences);
                        differences
                            .iter()
                            .zip(denominators.iter())
                            .map(|(a, b)| numerator * a * b)
                            .collect()
                    })
                    .collect(),
            )
        },
    )
}
