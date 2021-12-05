use std::cmp::{Ord,Ordering};
use std::collections::BinaryHeap;
use packetcrypt_util::util;

struct NwayItem<'a, T: Ord + Clone>
{
    list: &'a [T],
}
impl<'a, T: Ord + Clone> NwayItem<'a, T> {
    fn item(&self) -> Option<&'a T> {
        self.list.get(0)
    }
}
impl<'a, T: Ord + Clone> PartialEq for NwayItem<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.item() == other.item()
    }
}
impl<'a, T: Ord + Clone> Eq for NwayItem<'a, T> {}
impl<'a, T: Ord + Clone> PartialOrd for NwayItem<'a, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.item().partial_cmp(&self.item())
    }
}
impl<'a, T: Ord + Clone> Ord for NwayItem<'a, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Inverted so that we'll get bottom values first, though BinaryHeap is top-down
        other.item().cmp(&self.item())
    }
}
pub struct Nway<'a, T: Ord + Clone> {
    heap: BinaryHeap<NwayItem<'a, T>>,
    update_list: Option<&'a [T]>,
}
impl<'a, T: Ord + Clone> Nway<'a, T> {
    pub fn add_list(&mut self, list: &'a [T]) {
        self.heap.push(NwayItem { list });
    }
    pub fn with_capacity(initial: usize) -> Self {
        Self{ update_list: None, heap: BinaryHeap::with_capacity(initial) }
    }
}
impl<'a, T: Ord + Clone> Iterator for Nway<'a, T> {
    type Item = T;
    fn next(&mut self) -> Option<T> {
        if let Some(ul) = self.update_list.take() {
            self.add_list(ul);
        }
        if let Some(ii) = self.heap.pop() {
            let out = ii.list[0].clone();
            if ii.list.len() > 1 {
                util::prefetch(&ii.list[1]);
                self.update_list = Some(&ii.list[1..]);
            }
            Some(out)
        } else {
            None
        }
    }
}