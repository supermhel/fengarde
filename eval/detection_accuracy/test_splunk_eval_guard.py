"""Regression: Q13 subset fetch leaves LFS pointers by design; splunk_eval must
fail only when NOTHING was pulled, and grade the fetched files otherwise."""
import contextlib, importlib.util, io, pathlib, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("splunk_eval", HERE / "splunk_eval.py")
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)

PTR = "version https://git-lfs.github.com/spec/v1\noid sha256:0\nsize 1\n"


def run(files):
    root = pathlib.Path(tempfile.mkdtemp())
    d = root / "atk"
    for name, text in files.items():
        (d / name).parent.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(text)
    se.SA, se.OUT = d, root / "out.json"
    se._missing_tracked_logs = lambda: []
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = se.main()
    return rc, buf.getvalue()


rc, out = run({"T1/a.log": PTR, "T2/b.log": PTR})
assert rc == 1 and "none were pulled" in out, (rc, out)
rc, out = run({"T1/a.log": PTR, "T2/b.log": "<Event xmlns='x'></Event>"})
assert rc == 0 and "left un-pulled" in out, (rc, out)
print("[OK] splunk_eval: all-pointer tree fails loudly; subset fetch (mixed) grades the fetched files")
