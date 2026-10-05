/-  types
/~  numbers  seed:types  /numbers
/~  empty  @ud  /empty
/%  plain  %noun
/%  named  %number
/%  chained  %chain
/$  grown  %source  %target
/$  grabbed  %missing  %target
/$  fallen  %broken  %target
/$  identity  %unknown  %unknown
/$  nouned  %source  %noun
/*  raw  %oct  /bytes/oct
/*  decoded  %result  /bytes/oct
/*  hoon-text  %hoon  /source/hoon
:-  !>(.)
:*  (add (~(got by numbers) %a) (~(got by numbers) %b))
    ~(wyt by empty)
    (pact:plain 1 42)
    (pact:named 1 43)
    (pact:chained 1 44)
    (grown 41)
    (grabbed 41)
    (fallen 41)
    (identity 42)
    (nouned 41)
    p.raw
    decoded
    =(hoon-text 'not a program\0a')
==
