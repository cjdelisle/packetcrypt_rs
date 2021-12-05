use std::cmp::{Ord,Ordering};
use std::collections::BinaryHeap;
use crate::types::AnnData;

struct NwayItem<'a>
{
    list: &'a [AnnData],
}
impl<'a> NwayItem<'a> {
    fn item(&self) -> Option<&'a AnnData> {
        self.list.get(0)
    }
}
impl<'a> PartialEq for NwayItem<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.item() == other.item()
    }
}
impl<'a> Eq for NwayItem<'a> {}
impl<'a> PartialOrd for NwayItem<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.item().partial_cmp(&self.item())
    }
}
impl<'a> Ord for NwayItem<'a> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Inverted so that we'll get bottom values first, though BinaryHeap is top-down
        other.item().cmp(&self.item())
    }
}
pub struct Nway<'a> {
    heap: BinaryHeap<NwayItem<'a>>,
}
impl<'a> Nway<'a> {
    pub fn add_list(&mut self, list: &'a [AnnData]) {
        self.heap.push(NwayItem { list });
    }
    pub fn with_capacity(initial: usize) -> Self {
        Self{ heap: BinaryHeap::with_capacity(initial) }
    }
    pub fn next_multi(&mut self, out: &mut [AnnData]) -> usize {
        let count = out.len();
        let mut v = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(ii) = self.heap.pop() {
                v.push(ii);
            } else {
                break;
            }
        }
        let mut new_min = u64::MAX;
        for (i, ii) in v.iter().enumerate() {
            if ii.list.len() > 1 {
                if new_min > ii.list[1].hash_pfx {
                    new_min = ii.list[1].hash_pfx;
                }
            }
            if (i+4) < v.len() {
                let nv = &v[i+4];
                if nv.list.len() > 1 {
                    prefetch(&nv.list[1]);
                }
            }
        }
        let mut out_idx = 0;
        for ii in v.iter_mut() {
            if ii.list[0].hash_pfx < new_min {
                out[out_idx] = ii.list[0].clone();
                out_idx += 1;
                ii.list = &ii.list[1..];
            }
        }
        for ii in v.iter_mut() {
            if !ii.list.is_empty() {
                self.add_list(ii.list);
            }
        }
        out_idx
    }
}
impl<'a> Iterator for Nway<'a> {
    type Item = AnnData;
    fn next(&mut self) -> Option<AnnData> {
        if let Some(ii) = self.heap.pop() {
            let out = ii.list[0].clone();
            if ii.list.len() > 1 {
                self.add_list(&ii.list[1..]);
            }
            Some(out)
        } else {
            None
        }
    }
}
fn prefetch<T>(t: &T) {
    let p = t as *const T as *const i8;
    #[cfg(all(target_arch = "x86_64", target_feature = "sse"))]
    unsafe { core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(p) }
}