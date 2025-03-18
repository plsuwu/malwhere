use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;
use windows::core::{PCSTR, PCWSTR};

pub trait HashFunction {

    type Output;

    fn hash_str(&self, s: &str) -> Self::Output;

    fn hash_vec(&self, v: Vec<&str>) -> Vec<Self::Output> {
        v.iter().map(|&s| self.hash_str(s)).collect()
    }
}

pub trait Hashable<H: HashFunction> {
    type Output;
    fn hash_with(&self, hasher: &H) -> Self::Output;
}

impl<T, H> Hashable<H> for T
where
    T: HashableString,
    H: HashFunction,
{
    type Output = H::Output;

    fn hash_with(&self, hasher: &H) -> Self::Output {
        self.with_str(|s| hasher.hash_str(s))
    }
}

impl<T, H> Hashable<H> for Vec<T>
where
    T: HashableString,
    H: HashFunction,
{
    type Output = Vec<H::Output>;

    fn hash_with(&self, hasher: &H) -> Self::Output {
        self.with_vec(|strs| strs.iter().map(|&s| hasher.hash_str(s)).collect())
    }
}

pub trait HashableString {
    fn with_str<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R;
}

pub trait HashableVec {
    fn with_vec<F, R>(&self, f: F) -> R
    where
        F: FnOnce(Vec<&str>) -> R;
}

impl<T> HashableVec for Vec<T>
where
    T: HashableString,
{
    fn with_vec<F, R>(&self, f: F) -> R
    where
        F: FnOnce(Vec<&str>) -> R,
    {
        let owned: Vec<String> = self
            .iter()
            .map(|s| s.with_str(|val| val.to_owned()))
            .collect();

        let refs: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();

        f(refs)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub struct StringHasher<H> {
    hash_func: H,
}

impl<H: HashFunction> StringHasher<H> {
    /// Instantiate a hashing function object
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use windows::core::PCSTR;
    /// use common::hashing::djb::Djb;
    /// use common::hashing::traits::StringHasher;
    ///
    /// // create a new `HashFunction` object
    /// let djb = StringHasher::new(Djb);
    ///
    /// // call its `.hash()` method on a `&str`
    /// let hash = djb.hash("omg hiii");
    ///
    /// // can take `PCSTR`- and `PCWSTR`-type strings
    /// let ansi_string = PCSTR::from_raw("omg hii".as_ptr());
    /// let hash = djb.hash(ansi_string);
    ///
    /// // can take `u8` and `u16` pointer types
    /// let str_ptr = "omg hiii".as_ptr();
    /// let hash = djb.hash(str_ptr);
    /// ```
    ///
    /// > Note that the pointer conversion simply invokes the `from_raw()` method for that
    /// > respective string type under the hood.
    pub fn new(hash_func: H) -> Self {
        Self { hash_func }
    }

    /// Hashes a string using the constructed `HashFunction`
    pub fn hash<T: Hashable<H>>(&self, value: T) -> T::Output {
        value.hash_with(&self.hash_func)
    }
}

impl HashableString for &str {
    fn with_str<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&str) -> R,
    {
        f(self)
    }
}

macro_rules! win_string_type {
    ($($ty:ty),*) => {
        $(
            impl HashableString for $ty {
                fn with_str<F, R>(&self, f: F) -> R
                where
                F: FnOnce(&str) -> R,
                {
                    let string = unsafe { self.to_string().unwrap_or_default() };
                    f(&string)
                }
            }
        )*
    }
}

macro_rules! win_ptr_type {
    ($(($ty:ty,$wrapper:ty)),*) => {
        $(
            impl HashableString for $ty {
                fn with_str<F, R>(&self, f: F) -> R
                where
                    F: FnOnce(&str) -> R,
                 {
                    let wrapped = <$wrapper>::from_raw(*self);
                    wrapped.with_str(f)
                 }
            }
        )*
    }
}

win_string_type!(PCWSTR, PCSTR);
win_ptr_type!((*const u8, PCSTR), (*const u16, PCWSTR));
