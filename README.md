### License

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

### Keccak (SNARK)   i5-12600KF   3.70 GHz

| Msg, bytes | To build a circuit, s | To prove, s | To verify, s | Proof size, bytes | 
|------------|-----------------------|-------------|--------------|-------------------|
| 1          | 4.1458                | 6.3075      | 0.0564       | 159_148           |
| 1_000      | 4.3148                | 6.5402      | 0.0602       | 159_148           | 
| 10_000     | 4.0895                | 7.0701      | 0.0701       | 159_148           | 
| 100_000    | 9.4426                | 37.9739     | 0.0753       | 165_676           | 


### How to run
```
cd hashes/keccak_ctl
RUSTFLAGS=-Ctarget-cpu=native cargo run --release
```
