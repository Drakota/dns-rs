use rand::prelude::SliceRandom;

pub trait RandomElement {
    type Item;
    fn get_random_element(&self) -> Option<Self::Item>;
}

impl<T> RandomElement for [T]
where
    T: Clone,
{
    type Item = T;

    fn get_random_element(&self) -> Option<Self::Item> {
        if self.is_empty() {
            None
        } else {
            Some(self.choose(&mut rand::thread_rng()).unwrap().clone())
        }
    }
}
