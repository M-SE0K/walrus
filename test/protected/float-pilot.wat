(module
  (func $sum_f32 (param $n i32) (param $step f32) (result f32)
    (local $i i32) (local $sum f32)
    block $done
      loop $again
        local.get $i local.get $n i32.ge_u br_if $done
        local.get $sum local.get $step f32.add local.set $sum
        local.get $i i32.const 1 i32.add local.set $i
        br $again
      end
    end
    local.get $sum)
  (func $sum_f64 (param $n i64) (param $step f64) (result f64)
    (local $i i64) (local $sum f64)
    block $done
      loop $again
        local.get $i local.get $n i64.ge_u br_if $done
        local.get $sum local.get $step f64.add local.set $sum
        local.get $i i64.const 1 i64.add local.set $i
        br $again
      end
    end
    local.get $sum)
  (func (export "float32_1000") (result f32) i32.const 1000 f32.const 0.5 call $sum_f32)
  (func (export "float64_1000") (result f64) i64.const 1000 f64.const 0.5 call $sum_f64)
  (func (export "float32_10m") (result f32) i32.const 10000000 f32.const 0.5 call $sum_f32)
  (func (export "float64_10m") (result f64) i64.const 10000000 f64.const 0.5 call $sum_f64))
