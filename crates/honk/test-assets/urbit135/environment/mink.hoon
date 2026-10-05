::  Virtual evaluation, namespaces, trace order, and nested scry failures.
|^
  :~  [%constant (mink [0 %1 42] reply)]
      [%null-constant (mink [0 %1 42] ~)]
      [%crash (mink [0 %0 0] reply)]
      [%null-crash (mink [0 %0 0] ~)]
      [%malformed (mink [0 42] reply)]
      [%unknown-op (mink [0 %42 0] reply)]
      [%malformed-tail (mink [0 [[%1 42] 42]] reply)]
      [%malformed-argument (mink [0 %4 42] reply)]
      [%malformed-eval (mink [0 [%2 [%1 0] 42]] reply)]
      [%scry (mink [0 scry] reply)]
      [%null-scry (mink [0 scry] ~)]
      [%blocked (mink [0 scry] |=(^ ~))]
      [%missing (mink [0 scry] |=(^ `~))]
      [%trace (mink [0 traced] reply)]
      [%missing-trace (mink [0 [%11 [%mean [%1 17]] scry]] |=(^ `~))]
      [%nested-crash (run |.((mink [0 scry] |=(^ !!))))]
      [%nested-success (run |.((mink [0 scry] reply)))]
      [%nested-blocked (run |.((mink [0 scry] |=(^ ~))))]
      [%handler-scry (run |.((mink [0 scry] |=([ref=* path=*] ``.*([ref path] scry)))))]
  ==
++  scry  [%12 [%1 %read] [%1 /example]]
++  traced  [%11 [%mean [%1 17]] [%11 [%mean [%1 23]] [%0 0]]]
++  reply  |=([ref=* path=*] ``[ref path])
++  run
  |=  trap=$-(* *)
  (mink [trap %9 2 %0 1] reply)
--
