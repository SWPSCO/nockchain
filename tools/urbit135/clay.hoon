::  Reference assembly for the desk fixture, using Clay's vase operations.
::  All compilation and evaluation run inside pinned Vere.
|=  [base=vase files=(map path [size=@ud data=@])]
|^
  =/  env  (push base %types (module /sur/types/hoon))
  =/  vaz  (vang | /entry/hoon)
  =/  spec  (rash 'seed:types' wyde:vaz)
  =/  members
    %-  ~(gas by *(map @ta vase))
    :~  [%a (module /numbers/a/hoon)]
        [%b (module /numbers/b/hoon)]
    ==
  =.  env  (push env %numbers (directory env spec members))
  =.  env  (push env %empty (directory env [%base %atom %ud] ~))
  =.  env  (push env %plain (nave %noun))
  =.  env  (push env %named (nave %number))
  =.  env  (push env %chained (nave %chain))
  =.  env  (push env %grown (tube %source %target))
  =.  env  (push env %grabbed (tube %missing %target))
  =.  env  (push env %fallen (tube %broken %target))
  =.  env  (push env %identity (tube %unknown %unknown))
  =.  env  (push env %nouned (tube %source %noun))
  =.  env  (push env %raw (file /bytes/oct %oct))
  =.  env  (push env %decoded (file /bytes/oct %result))
  (push env %hoon-text (file /source/hoon %hoon))
::
++  push
  |=  [env=vase name=@tas value=vase]
  ^-  vase
  (slop value(p [%face name p.value]) env)
::
++  module
  |=  pax=path
  ^-  vase
  =/  source  data:(~(got by files) pax)
  =/  vaz  (vang | pax)
  (slap base (rash source (ifix [gay gay] (stag %tssg (most gap tall:vaz)))))
::
++  mark-core
  |=  name=@tas
  ^-  (unit vase)
  =/  pax  /mar/[name]/hoon
  ?.  (~(has by files) pax)  ~
  `(module pax)
::
++  has-arm
  |=  [arm=@tas mark=@tas core=vase]
  ^-  ?
  ?.  (slob arm p.core)  |
  ?~  rib=(~(mole vi |) |.((slub core [%wing ~[arm]])))  |
  (slob mark p.u.rib)
::
++  tube
  |=  [from=@tas to=@tas]
  ^-  vase
  ?:  =(from to)  (slap base !,(*hoon same))
  ?:  =([%mime %hoon] [from to])
    (slap base !,(*hoon |=(m=mime q.q.m)))
  =/  old  (mark-core from)
  =/  new  (mark-core to)
  ?:  &(?=(^ old) (has-arm %grow to u.old))
    %+  slub  u.old(p [%face %cor p.u.old])
    :+  %brcl  !,(*hoon v=+<.cor)
    :+  %sggr
      [%spin %cltr [%sand %t (crip "grow-{<from>}->{<to>}")] ~]
    :+  %tsgl  limb/to
    !,(*hoon ~(grow cor v))
  ?:  &(?=(^ new) (has-arm %grab from u.new))
    =;  value=vase
      ?>  ?=(^ q.value)
      value
    %+  slub  u.new
    :+  %sggr
      [%spin %cltr [%sand %t (crip "grab-{<from>}->{<to>}")] ~]
    tsgl/[limb/from limb/%grab]
  ?:  =(%noun to)  (slap base !,(*hoon same))
  ~|(no-cast-between+[from to] !!)
::
++  file
  |=  [pax=path mark=@tas]
  ^-  vase
  =/  stored  (head (flop pax))
  =/  content  (~(got by files) pax)
  =/  mime  (slam (slap base !,(*hoon mime)) [%noun /text/plain content])
  (slam (tube stored mark) (slam (tube %mime stored) mime))
::
++  directory
  |=  [env=vase spec=spec members=(map @ta vase)]
  ^-  vase
  =/  type-val  (~(play ut p.env) [%kttr spec])
  =/  type-map
    %-  ~(play ut p.env)
    [%kttr %make [%wing ~[%map]] ~[[%base %atom %ta] spec]]
  :-  type-map
  |-  ^-  *
      ?~  members  ~
      ?>  (~(nest ut type-val) | p.q.n.members)
      :-  [p.n.members q.q.n.members]
      [$(members l.members) $(members r.members)]
::
++  with-faces
  =|  res=(unit vase)
  |=  values=(list [face=@tas value=vase])
  ^-  vase
  ?~  values  (need res)
  =/  face  value.i.values(p [%face face.i.values p.value.i.values])
  =.  res  `?~(res face (slop face u.res))
  $(values t.values)
::
++  nave
  |=  mark=@tas
  ^-  vase
  =/  cor  (need (mark-core mark))
  =/  grad  (slap cor limb/%grad)
  ?^  q.grad
    %+  slub  (slop cor(p [%face %cor p.cor]) base)
    !,  *hoon
    =/  typ  _+<.cor
    =/  dif  _*diff:grad:cor
    ^-  (nave:clay typ dif)
    |%
    ++  diff  |=([old=typ new=typ] (diff:~(grad cor old) new))
    ++  form  form:grad:cor
    ++  join
      |=  [a=dif b=dif]
      ^-  (unit (unit dif))
      ?:  =(a b)  ~
      `(join:grad:cor a b)
    ++  mash
      |=  [a=[=ship =desk =dif] b=[=ship =desk =dif]]
      ^-  (unit dif)
      ?:  =(dif.a dif.b)  ~
      `(mash:grad:cor a b)
    ++  pact  |=([v=typ d=dif] (pact:~(grad cor v) d))
    ++  vale  noun:grab:cor
    --
  =/  parent  !<(@tas grad)
  =/  deg  $(mark parent)
  =/  tub  (tube mark parent)
  =/  but  (tube parent mark)
  =/  nav  (slap base !,(*hoon nave:clay))
  %+  slub  (with-faces deg+deg tub+tub but+but cor+cor nave+nav ~)
  !,  *hoon
  =/  typ  _+<.cor
  =/  dif  _*diff:deg
  ^-  (nave typ dif)
  |%
  ++  diff
    |=  [old=typ new=typ]
    ^-  dif
    (diff:deg (tub old) (tub new))
  ++  form  form:deg
  ++  join  join:deg
  ++  mash  mash:deg
  ++  pact
    |=  [v=typ d=dif]
    ^-  typ
    (but (pact:deg (tub v) d))
  ++  vale  noun:grab:cor
  --
--
