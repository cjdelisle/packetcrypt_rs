### Fields on a stats log line:

```
1637846499 INFO blkmine.rs:922 shr: 0  real: 183 Ke/s eff: 85 Ee/s   anns: 87195648 @ 63  rdy: 113082368 spr: 2883584 imm: 884736 cls: 109 <- [ 206, 209, 196, 200, 199, 198, 200, 195, 194, 206 ]          
```

shr: number of shares since the previous stats log
<br>real: number of actual encryptions per second, the speed of your miner
<br>eff: effective mining power in "synthetic encryptions per second"
<br>anns: number of anns currently being mined with
<br>@: current minimum difficulty of anns being mined
<br>rdy: number of anns which are mineable
<br>spr: number of spare bufs for anns to be stored in
<br>imm: number of immature anns, which will be able to be mined with after a few blocks pass
<br>cls: number of classes of anns
<br><-: number of thousands of anns downloaded from each of the ann handlers
