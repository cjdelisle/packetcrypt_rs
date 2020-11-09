use crate::util;
use anyhow::Result;
use crossbeam_channel::unbounded;
use std::fs::File;
use std::io::prelude::*;

#[global_allocator]
static LEAK_TRACER: leak_detect_allocator::LeakTracerDefault =
    leak_detect_allocator::LeakTracerDefault::new();

struct AddrSize {
    addr: usize,
    size: usize,
}

enum AllocEnt {
    Alloc(AddrSize),
    Frame(usize),
}

struct Req {
    outfile: String,
    resp: crossbeam_channel::Sender<Result<()>>,
}

pub struct Allocator {
    send: crossbeam_channel::Sender<Req>,
}

fn write_mem_allocations(ld_size: usize, outfile: String) -> Result<()> {
    let mut count: usize = 0;
    let mut count_size: usize = 0;
    let mut file = File::create(outfile)?;
    let mut allocs: Vec<AllocEnt> = Vec::new();
    LEAK_TRACER.now_leaks(|addr, frames| {
        if count % 100 == 0 {
            println!("Snapshotting memory trace [{}]", count);
        }
        count += 1;
        let mut it = frames.iter();
        // first is the alloc size
        let size = it.next().unwrap_or(&0);
        if *size == ld_size {
            return true;
        }
        count_size += *size;
        allocs.push(AllocEnt::Alloc(AddrSize { addr, size: *size }));
        for addr in it {
            allocs.push(AllocEnt::Frame(*addr));
        }
        true // continue until end
    });
    let mut i = 0;
    for ent in allocs {
        // Resolve this instruction pointer to a symbol name
        match ent {
            AllocEnt::Alloc(al) => {
                if i % 100 == 0 {
                    println!("Writing out memory trace [{}]", i);
                }
                i += 1;
                &file.write_all(
                    &format!("memory allocaction: {:#x}, size: {}\n", al.addr, al.size)
                        .into_bytes()[..],
                )?;
            }
            AllocEnt::Frame(addr) => {
                let name = unsafe { LEAK_TRACER.get_symbol_name(addr) };
                file.write_all(
                    &format!("\t0x{:x}: {}\n", addr, name.unwrap_or("unknown".to_owned()))
                        .into_bytes()[..],
                )?;
            }
        }
    }
    file.write_all(
        &format!(
            "\ntotal address:{}, bytes:{}, internal use for allocator:{} bytes\n",
            count,
            count_size,
            ld_size * 2,
        )
        .into_bytes()[..],
    )?;
    //file.flush().await?;
    println!("Writing memory trace complete");
    Ok(())
}

impl Allocator {
    pub async fn write_mem_allocations(&self, outfile: String) -> Result<()> {
        let (resp, recv_resp) = unbounded();
        self.send.send(Req { outfile, resp }).unwrap();
        loop {
            if let Ok(r) = recv_resp.try_recv() {
                return r;
            } else {
                util::sleep_ms(5000).await;
            }
        }
    }
}

pub async fn alloc_init() -> Result<Allocator> {
    let (s, r) = unbounded::<Req>();
    let ld_size = LEAK_TRACER.init();
    std::thread::spawn(move || loop {
        let req = r.recv().unwrap();
        let res = write_mem_allocations(ld_size, req.outfile);
        req.resp.send(res).unwrap();
    });
    Ok(Allocator { send: s })
}
