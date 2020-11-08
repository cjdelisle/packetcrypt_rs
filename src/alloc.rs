use anyhow::Result;
use tokio::fs::File;
use tokio::prelude::*;

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

pub struct Allocator(usize);

impl Allocator {
    pub async fn write_mem_allocations(&self, outfile: &str) -> Result<()> {
        let mut count: usize = 0;
        let mut count_size: usize = 0;
        let mut file = File::create(outfile).await?;
        let mut allocs: Vec<AllocEnt> = Vec::new();
        LEAK_TRACER.now_leaks(|addr, frames| {
            if count % 100 == 0 {
                println!("Snapshotting memory trace [{}]", count);
            }
            count += 1;
            let mut it = frames.iter();
            // first is the alloc size
            let size = it.next().unwrap_or(&0);
            if *size == self.0 {
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
                    &file
                        .write_all(
                            &format!("memory allocaction: {:#x}, size: {}\n", al.addr, al.size)
                                .into_bytes()[..],
                        )
                        .await?;
                }
                AllocEnt::Frame(addr) => {
                    let mut ret: Option<String> = None;
                    backtrace::resolve(addr as *mut _, |symbol| {
                        ret = symbol.name().map(|x| x.to_string())
                    });
                    file.write_all(
                        &format!(
                            "\t0x{:x}: {}\n",
                            addr,
                            ret.unwrap_or("<unknown>".to_owned())
                        )
                        .into_bytes()[..],
                    )
                    .await?;
                }
            }
        }
        file.write_all(
            &format!(
                "\ntotal address:{}, bytes:{}, internal use for leak-detect-allacator:{} bytes\n",
                count,
                count_size,
                self.0 * 2,
            )
            .into_bytes()[..],
        )
        .await?;
        //file.flush().await?;
        println!("Writing memory trace complete");
        Ok(())
    }
}

pub async fn alloc_init() -> Result<Allocator> {
    Ok(Allocator(LEAK_TRACER.init()))
}
