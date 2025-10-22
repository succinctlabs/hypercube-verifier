use std::borrow::Borrow;

pub trait OwnedBorrow<T: ?Sized>: Borrow<T> + Send + Sync + Clone + 'static {}

impl<T: ?Sized, V> OwnedBorrow<T> for V where V: Borrow<T> + Send + Sync + Clone + 'static {}
