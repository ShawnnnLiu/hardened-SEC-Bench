"""Case table for mruby.cve-2022-0717 (index assignment with 14 register
arguments; upstream fix f72315575, mrbgems/mruby-compiler/core/codegen.c).

Prints one TSV row per case: name, family, program. The programs are run by
scripts/arypush_run_cases.sh inside the instance container; the expected
values are the results of the image's CRuby 2.7.0 (scripts/arypush_expected.tsv,
written by `arypush_run_cases.sh ruby`).

gen_assignment() compiles `recv[args] = rhs` as a call of `[]=` with the
right-hand side as the last argument. After the right-hand side it either
adds one register argument (`n < 14`) or appends the right-hand side to the
packed argument array with OP_ARYPUSH. At the base commit the second branch
is taken for n == 14, although 14 arguments are 14 separate registers and
nothing is packed, so OP_ARYPUSH is applied to the register of the 14th
argument and the call reads 14 registers. The developer patch makes the
right-hand side the 15th value and packs the 15 values with OP_ARRAY.

Every program defines a receiver class R whose `[]=` records its arguments
in $g (and whose `[]` returns $v, for the op-assign rows), runs one statement
and prints `<<value>>`, or `<<E:ExceptionClass>>` when the statement raises.

Families (the first word of the family column):
  f1   exactly 14 positional index arguments, no keyword, no splat: the
       reported construct. The 14th argument is an immediate (Integer, nil,
       true, false, Symbol, Float), a heap object (String, Object) or an
       Array; the statement is a plain assignment, a value-used assignment,
       a multiple assignment, a for variable or a rescue target; the
       receiver is R, an Array (the PoC construct) or a String. `poc` runs
       the dataset file /testcase/poc_decoded and is judged by the presence
       of a sanitizer report only.
  f2   13 positional index arguments and keyword arguments, so n == 14 after
       the keyword hash: the same post-rhs branch, reached through the
       keyword branch. `poc1276` is the PoC of mruby.cve-2022-1276.
  f3   0 to 12 positional index arguments and keyword arguments: no
       OP_ARYPUSH; the keyword branch of this tree pushes the hash twice
       (the defect of mruby.cve-2022-1276), so the right-hand side is not
       the last register the call reads.
  b    boundaries that do not reach the post-rhs branch with n == 14: 13 or
       15 and more positional arguments, a splat, 14 positional arguments
       with a keyword (packed at limit 13), op-assign (a separate code path
       with limit 13) and an explicit `.[]=` call.
  c    controls: small index and attribute assignments on R, Array, Hash.
"""
import sys

PRE = 'class R;def []=(*a);$g=a;end;def [](*a);$v;end;attr_accessor :x;end;o=R.new;'


def args(lo, hi, last=None):
    a = [str(i) for i in range(lo, hi + 1)]
    if last is not None:
        a.append(last)
    return ",".join(a)


def prog(stmt, out):
    return (PRE + 'begin;' + stmt + ';print "<<",(' + out + '),">>";'
            'rescue => e;print "<<E:",e.class,">>";end')


A13 = args(1, 13)
A14 = args(1, 14)
rows = []


def case(name, family, stmt, out='$g.inspect'):
    rows.append((name, family, prog(stmt, out)))


# f1: 14 positional arguments, the 14th argument varies (the ARYPUSH target)
rows.append(("poc", "f1 dataset PoC file", "@/testcase/poc_decoded"))
case("f1_int", "f1 immediate Integer", f"o[{A14}]=:r")
case("f1_zero", "f1 immediate Integer 0", f"o[{args(1, 13, '0')}]=:r")
case("f1_nil", "f1 immediate nil", f"o[{args(1, 13, 'nil')}]=:r")
case("f1_true", "f1 immediate true", f"o[{args(1, 13, 'true')}]=:r")
case("f1_false", "f1 immediate false", f"o[{args(1, 13, 'false')}]=:r")
case("f1_sym", "f1 immediate Symbol", f"o[{args(1, 13, ':s')}]=:r")
case("f1_float", "f1 immediate Float", f"o[{args(1, 13, '1.5')}]=:r")
case("f1_str", "f1 heap String", f"o[{args(1, 13, chr(34) + 's' + chr(34))}]=:r")
case("f1_obj", "f1 heap Object", f"o[{args(1, 13, 'Object.new')}]=:r", '$g.size.to_s')
case("f1_ary", "f1 Array argument", f"o[{args(1, 13, '[0]')}]=:r")
case("f1_arysrc", "f1 Array argument, source", f"x=[0];o[{args(1, 13, 'x')}]=:r", 'x.inspect')
case("f1_arrrecv", "f1 Array receiver (PoC construct)", f"[:_][{','.join(['0'] * 14)}]=:N", '"ok"')
case("f1_strrecv", "f1 String receiver", f's="abc";s[{A14}]=:r', 's')
case("f1_val", "f1 value used", f"y=(o[{A14}]=:r)", '[y,$g].inspect')
case("f1_masgn", "f1 multiple assignment", f"o[{A14}],b=:r,:s", '[$g,b].inspect')
case("f1_for", "f1 for variable", f"for o[{A14}] in [:r];end")
case("f1_rescue", "f1 rescue target", f'begin;raise "x";rescue => o[{A14}];end',
     '[$g.size,$g[0,14],$g[14].class].inspect')

# f2: 13 positional arguments and keyword arguments (n == 14 after the hash)
case("f2_kw", "f2 keyword pair", f"o[{A13},k:99]=:r")
case("f2_dsplat", "f2 double splat", f"h={{k:99}};o[{A13},**h]=:r")
case("f2_strrecv", "f2 String receiver", f's="abc";s[{A13},k:99]=:r', 's')
case("poc1276", "f2 mruby.cve-2022-1276 PoC", "0..% = [0,0,0,0,0,0,0,0,0,0,0,0,0,**{}] = 0", '"ok"')

# f3: 0 to 12 positional arguments and keyword arguments
case("f3_kw0", "f3 keyword, 0 positional", "o[k:99]=:r")
case("f3_kw1", "f3 keyword, 1 positional", "o[1,k:99]=:r")
case("f3_kw12", "f3 keyword, 12 positional", f"o[{args(1, 12)},k:99]=:r")
case("f3_dsplat1", "f3 double splat, 1 positional", "h={k:99};o[1,**h]=:r")

# b: boundaries
case("b_a13", "b 13 positional", f"o[{A13}]=:r")
case("b_a15", "b 15 positional", f"o[{args(1, 15)}]=:r")
case("b_a20", "b 20 positional", f"o[{args(1, 20)}]=:r")
case("b_splat14", "b 13 positional and a splat", f"a=[14];o[{A13},*a]=:r")
case("b_splatall", "b splat of 14", "a=(1..14).to_a;o[*a]=:r")
case("b_kw14", "b 14 positional and a keyword", f"o[{A14},k:99]=:r")
case("b_kwsplat", "b splat and a keyword", "a=[1];o[*a,k:99]=:r")
case("b_opor14", "b op-assign ||= with 14", f"$v=nil;o[{A14}]||=:r")
case("b_opadd14", "b op-assign += with 14", f"$v=1;o[{A14}]+=1")
case("b_opor13", "b op-assign ||= with 13", f"$v=nil;o[{A13}]||=:r")
case("b_call15", "b explicit []= call with 15", f"o.[]=({A14},:r)")

# c: controls
case("c_idx1", "c index 1", "o[1]=:r")
case("c_idx2", "c index 2", "o[1,2]=:r")
case("c_attr", "c attribute", "o.x=5", 'o.x.inspect')
case("c_array", "c Array#[]=", "a=[0,1,2];a[1]=:r", 'a.inspect')
case("c_array2", "c Array#[]= with length", "a=[0,1,2,3];a[1,2]=:r", 'a.inspect')
case("c_hash", "c Hash#[]=", "h={};h[:k]=1", 'h.inspect')
case("c_masgn2", "c multiple assignment, 2 index", "o[1,2],b=:r,:s", '[$g,b].inspect')

names = [r[0] for r in rows]
assert len(names) == len(set(names)), "duplicate case name"
for r in rows:
    assert "\t" not in "".join(r) and "\n" not in "".join(r)
    sys.stdout.write("\t".join(r) + "\n")
