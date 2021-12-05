use std::cmp::{Ord,Ordering};
use std::collections::BinaryHeap;

struct NwayItem<T: Ord, I: Iterator<Item = T>>
{
    item: T,
    iter: I,
}
impl<T: Ord, I: Iterator<Item = T>> PartialEq for NwayItem<T, I> {
    fn eq(&self, other: &Self) -> bool {
        self.item == other.item
    }
}
impl<T: Ord, I: Iterator<Item = T>> Eq for NwayItem<T, I> {}
impl<T: Ord, I: Iterator<Item = T>> PartialOrd for NwayItem<T, I> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.item.partial_cmp(&self.item)
    }
}
impl<T: Ord, I: Iterator<Item = T>> Ord for NwayItem<T, I> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Inverted so that we'll get bottom values first, though BinaryHeap is top-down
        other.item.cmp(&self.item)
    }
}
pub struct Nway<T: Ord, I: Iterator<Item = T>> {
    heap: BinaryHeap<NwayItem<T, I>>
}
impl<T: Ord, I: Iterator<Item = T>> Nway<T, I> {
    pub fn add_iter(&mut self, mut iter: I) {
        if let Some(item) = iter.next() {
            let x = NwayItem { item, iter };
            self.heap.push(x);
        }
    }
    pub fn with_capacity(initial: usize) -> Self {
        Self{ heap: BinaryHeap::with_capacity(initial) }
    }
}
impl<T: Ord, I: Iterator<Item = T>> Iterator for Nway<T, I> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        if let Some(ii) = self.heap.pop() {
            let out = ii.item;
            self.add_iter(ii.iter);
            Some(out)
        } else {
            None
        }
    }
}