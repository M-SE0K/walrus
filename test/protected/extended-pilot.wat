(module
  (memory 1 2)
  (global $processed (mut i32) (i32.const 0))
  (func $mix (param i32) (result i32)
    local.get 0 i32.const 7 i32.rotl
    local.get 0 i32.popcnt i32.xor)
  (func $fill_and_sum (param $n i32) (result i64)
    (local $i i32) (local $sum i64)
    block $done
      loop $again
        local.get $i local.get $n i32.ge_u br_if $done
        local.get $i i32.const 4 i32.mul local.get $i i32.store
        local.get $sum
        local.get $i i32.const 4 i32.mul i32.load i64.extend_i32_u
        i64.add local.set $sum
        local.get $i i32.const 1 i32.add local.set $i
        br $again
      end
    end
    local.get $n global.set $processed
    local.get $sum)
  (func $gcd (param $a i32) (param $b i32) (result i32)
    local.get $b i32.eqz
    if (result i32)
      local.get $a
    else
      local.get $b local.get $a local.get $b i32.rem_u call $gcd
    end)
  (func $combine (result i64)
    i32.const 1000 call $fill_and_sum
    i32.const 1071 i32.const 462 call $gcd i64.extend_i32_u i64.add
    global.get $processed i64.extend_i32_u i64.add
    i32.const 1 call $mix i64.extend_i32_u i64.add)
  (func (export "integer_mix") (result i32) i32.const 1 call $mix)
  (func (export "memory_sum") (result i64) i32.const 1000 call $fill_and_sum)
  (func (export "recursive_gcd") (result i32) i32.const 1071 i32.const 462 call $gcd)
  (func (export "combined") (result i64) call $combine)
  (func (export "processed") (result i32) global.get $processed))
