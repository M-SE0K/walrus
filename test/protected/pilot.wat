(module
  ;; Integer arithmetic and two conditional branches.
  (func $calc (param $x i32) (result i32)
    local.get $x
    i32.const 10
    i32.gt_s
    if (result i32)
      local.get $x
      i32.const 3
      i32.add
    else
      local.get $x
      i32.const 2
      i32.sub
    end)

  ;; --run-export accepts functions with no parameters in this revision.
  (func (export "calc_20") (result i32)
    i32.const 20
    call $calc)
  (func (export "calc_5") (result i32)
    i32.const 5
    call $calc)

  ;; Sum 1..n using an explicit Wasm loop. No memory or host imports.
  (func $sum_to_n (param $n i32) (result i64)
    (local $i i32)
    (local $sum i64)
    block $done
      loop $again
        local.get $i
        local.get $n
        i32.ge_u
        br_if $done

        local.get $i
        i32.const 1
        i32.add
        local.tee $i
        i64.extend_i32_u
        local.get $sum
        i64.add
        local.set $sum
        br $again
      end
    end
    local.get $sum)

  (func (export "sum_1000") (result i64)
    i32.const 1000
    call $sum_to_n)
  (func (export "sum_1m") (result i64)
    i32.const 1000000
    call $sum_to_n)

  (func (export "sum_10m") (result i64)
    i32.const 10000000
    call $sum_to_n)
)
