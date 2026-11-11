"""Case table for mruby.cve-2018-10199 (use-after-free in IO#initialize_copy;
upstream fix b51b21fc, mrbgems/mruby-io/src/io.c).

Prints one TSV row per case: name, family, program. The programs are run by
scripts/iocopy_run_cases.sh inside the instance container; the expected values
are the results of the image's CRuby 2.7.0 (scripts/iocopy_expected.tsv, written
by `iocopy_run_cases.sh ruby`). A program beginning with `@` names a file in the
container (the dataset PoC /testcase/uaf_file.rb) and is judged by the sanitizer
report only.

IO#initialize_copy is public in this mruby and private in CRuby, so every case
calls it as x.send(:initialize_copy, y): one program text runs on both. Only
deterministic values are printed (an exception class, closed?, data read back,
a count), never a descriptor number or object id. A case that needs a file uses
its own /tmp/iocopy_<name>.txt, creates it with "abc", and deletes it in an
ensure; the runner also clears /tmp/iocopy_* before and after the whole set.

Mechanism (base, io.c:555):

    mrb_get_args(mrb, "o", &orig);
    fptr_copy = (struct mrb_io *)DATA_PTR(copy);     /* 564 */
    if (fptr_copy != NULL) {                          /* 565 */
      fptr_finalize(mrb, fptr_copy, FALSE);           /* 566 */
      mrb_free(mrb, fptr_copy);                       /* 567  free receiver's old struct */
    }
    fptr_copy = (struct mrb_io *)mrb_io_alloc(mrb);   /* 569  alloc new struct */
    fptr_orig = io_get_open_fptr(mrb, orig);          /* 570  RAISES on non-IO/closed */
    DATA_TYPE(copy) = &mrb_io_type;                   /* 572 */
    DATA_PTR(copy) = fptr_copy;                       /* 573  store new struct */
    ...
    fptr_copy->fd = mrb_dup(mrb, fptr_orig->fd, &failed);

io_get_open_fptr (io.c:78) raises TypeError when orig is not an IO
(mrb_get_datatype) and IOError ("closed stream.") when its fd < 0. On the base
that raise at 570 happens AFTER the old struct was freed (566-567) and the new
one allocated (569) but BEFORE the new pointer is stored (573): the receiver's
DATA_PTR is left pointing to the freed old struct (a dangling pointer, read at
the next use or at exit-time GC finalization), and the new struct is leaked.

Invariant: every exit from IO#initialize_copy, normal or by an exception, leaves
the receiver's data pointer pointing to a live struct mrb_io (the old one or the
new one), never to freed memory, and the function never reads a struct after
freeing it. Narrowest form (the reported failure): no raise between the free of
the old struct and the store of the new pointer. Wider form: the self copy
(orig and copy the same object) must not free the struct it then reads.

The developer patch moves `fptr_orig = io_get_open_fptr(mrb, orig);` to right
after mrb_get_args, so the validation (and its possible raise) happens before the
free and the alloc. This fixes the reported failure (families r, u) and the
dup-closed leak (family d). It does NOT fix the self copy (family s): after the
patch io_get_open_fptr(orig) returns the receiver's live struct, the free then
frees it, and mrb_dup(mrb, fptr_orig->fd, ...) reads the freed struct (the
upstream #4005 report). Upstream commit c9275bbb ("mrb_io_initialize_copy should
not free existing fptr; fix #4005", 12 commits later) adds
`if (fptr_orig == fptr_copy) return copy;` to fix the self copy.

Families (first word of the family column):
  r   the reported failure: an open receiver (with a struct) and an argument
      that makes io_get_open_fptr raise (0, nil, "str", [], Object.new, a closed
      IO). The old struct is freed, the raise leaves DATA_PTR(copy) dangling,
      used at exit-time GC finalization. r_poc runs the dataset
      /testcase/uaf_file.rb. Expected CRuby: the exception class (TypeError or
      IOError); the receiver is unchanged.
  u   the same, with one use of the receiver after the rescued exception
      (closed?, close, sysread, fileno, an allocation loop then close): the use
      reads or writes the dangling struct. Expected CRuby: the use succeeds on
      the unchanged, still-open receiver.
  d   a fresh receiver through dup of a closed IO (file, pipe end): no struct is
      freed (DATA_PTR was NULL) so DATA_PTR is not left dangling, but the new
      struct is leaked (LeakSanitizer) and IOError is raised. Expected CRuby:
      IOError.
  s   the self copy (orig and copy the same open IO: file, IO.new(0), pipe end):
      the struct is freed, then read. On the base the read is inside
      io_get_open_fptr; after the developer patch it is inside mrb_dup. Expected
      CRuby: the receiver is returned unchanged.
  v   valid copies through the patched lines: copy one open IO onto another
      (the copy reads the other's data), dup an open file and an open pipe end.
      Expected CRuby: the copied data; OK on every build.
  c   controls: IO#initialize called again on an open IO with a valid descriptor
      and with an invalid mode string (mrb_io_initialize validates the mode
      before the free, so no dangling pointer), and a program with no IO copy.
"""

def g(body):
    return 'begin;' + body + ';rescue => e;print "<<E:",e.class,">>";end'

def gf(name, body):
    p = '/tmp/iocopy_' + name + '.txt'
    pre = 'p=' + repr(p) + ';File.open(p,"w"){|f|f.write("abc")};'
    return (pre + 'begin;' + body + ';rescue => e;print "<<E:",e.class,">>";'
            'ensure;(File.delete(p) rescue nil);end')

ROWS = [
    # r: the reported failure (receiver with a struct, argument raises; crash at exit GC)
    ("r_poc", "r dataset PoC uaf_file.rb (File.new(0); initialize_copy(0))",
        "@/testcase/uaf_file.rb"),
    ("r_file0_int", "r File.new(0), initialize_copy(0) non-IO -> TypeError",
        g('a=File.new(0);a.send(:initialize_copy,0);print "<<","noraise",">>"')),
    ("r_io0_nil", "r IO.new(0), initialize_copy(nil) -> TypeError",
        g('a=IO.new(0);a.send(:initialize_copy,nil);print "<<","noraise",">>"')),
    ("r_fileread_str", "r File read, initialize_copy('s') -> TypeError",
        gf('r_fileread_str', 'a=File.new(p);a.send(:initialize_copy,"s");print "<<","noraise",">>"')),
    ("r_filewrite_arr", "r File write, initialize_copy([]) -> TypeError",
        gf('r_filewrite_arr', 'a=File.new(p,"w");a.send(:initialize_copy,[]);print "<<","noraise",">>"')),
    ("r_pipe_obj", "r pipe read end, initialize_copy(Object.new) -> TypeError",
        g('r,w=IO.pipe;r.send(:initialize_copy,Object.new);print "<<","noraise",">>"')),
    ("r_popen_int", "r popen receiver (child pid), initialize_copy(0) -> TypeError",
        g('a=IO.popen("echo x");a.send(:initialize_copy,0);print "<<","noraise",">>"')),
    ("r_file_closedarg", "r File receiver, initialize_copy(closed File, same class) -> IOError",
        'p1="/tmp/iocopy_r_file_closedarg_1.txt";p2="/tmp/iocopy_r_file_closedarg_2.txt";File.open(p1,"w"){|f|f.write("abc")};File.open(p2,"w"){|f|f.write("abc")};begin;a=File.new(p1);c=File.new(p2);c.close;a.send(:initialize_copy,c);print "<<","noraise",">>";rescue => e;print "<<E:",e.class,">>";ensure;(File.delete(p1) rescue nil);(File.delete(p2) rescue nil);end'),
    # u: the reported failure with one use of the receiver after the rescue
    ("u_closed", "u File.new(0) raise, then closed? (unchanged, open)",
        g('a=File.new(0);(begin;a.send(:initialize_copy,0);rescue;end);print "<<",(a.closed?),">>"')),
    ("u_close", "u File.new(0) raise, then close",
        g('a=File.new(0);(begin;a.send(:initialize_copy,0);rescue;end);a.close;print "<<","closed",">>"')),
    ("u_sysread", "u File read raise, then sysread(1)",
        gf('u_sysread', 'a=File.new(p);(begin;a.send(:initialize_copy,0);rescue;end);print "<<",(a.sysread(1)),">>"')),
    ("u_fileno", "u File.new(0) raise, then fileno.class",
        g('a=File.new(0);(begin;a.send(:initialize_copy,0);rescue;end);print "<<",(a.fileno.class),">>"')),
    ("u_alloc_close", "u File.new(0) raise, alloc loop (reclaim), then close",
        g('a=File.new(0);(begin;a.send(:initialize_copy,0);rescue;end);1000.times{s=("x"*8)};a.close;print "<<","closed",">>"')),
    # d: fresh receiver through dup of a closed IO (leak on base, IOError)
    ("d_closed_file", "d dup of a closed File (temp file) -> IOError (base leaks new struct)",
        gf('d_closed_file', 'a=File.new(p);a.close;b=a.dup;print "<<","dupok",">>"')),
    ("d_closed_pipe", "d dup of a closed pipe end -> IOError (base leaks new struct)",
        g('r,w=IO.pipe;r.close;r2=r.dup;print "<<","dupok",">>"')),
    # s: the self copy (orig and copy the same open IO)
    ("s_file", "s self copy of an open File (base + dev both UAF; c9275bbb fixes)",
        gf('s_file', 'a=File.new(p);a.send(:initialize_copy,a);print "<<",(a.closed?),">>"')),
    ("s_io0", "s self copy of IO.new(0)",
        g('a=IO.new(0);a.send(:initialize_copy,a);print "<<",(a.closed?),">>"')),
    ("s_pipe", "s self copy of a pipe read end",
        g('r,w=IO.pipe;r.send(:initialize_copy,r);print "<<",(r.closed?),">>"')),
    # v: valid copies through the patched lines
    ("v_copy_onto", "v copy an open IO onto an open receiver (reads other's data)",
        'p1="/tmp/iocopy_v_copy_onto_1.txt";p2="/tmp/iocopy_v_copy_onto_2.txt";File.open(p1,"w"){|f|f.write("abc")};File.open(p2,"w"){|f|f.write("xyz")};begin;a=File.new(p1);b=File.new(p2);a.send(:initialize_copy,b);print "<<",(a.sysread(1)),">>";rescue => e;print "<<E:",e.class,">>";ensure;(File.delete(p1) rescue nil);(File.delete(p2) rescue nil);end'),
    ("v_dup_file", "v dup an open File, read through the copy",
        gf('v_dup_file', 'a=File.new(p);b=a.dup;v=b.sysread(1);a.close;b.close;print "<<",(v),">>"')),
    ("v_dup_pipe", "v dup an open pipe read end, read through the copy",
        g('r,w=IO.pipe;w.write("x");w.close;r2=r.dup;v=r2.read(1);r.close;r2.close;print "<<",(v),">>"')),
    # c: controls
    ("c_reinit_valid", "c IO#initialize again with a valid fd (no dangling)",
        g('a=IO.new(0);a.send(:initialize,0);print "<<","reinit",">>"')),
    ("c_reinit_badmode", "c IO#initialize again with an invalid mode (raises before free)",
        g('a=IO.new(0);a.send(:initialize,0,"zzz");print "<<","noraise",">>"')),
    ("c_noio", "c no IO copy at all",
        g('print "<<",(1+1),">>"')),
]

for name, family, program in ROWS:
    print(name + "\t" + family + "\t" + program)
