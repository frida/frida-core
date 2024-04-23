from pathlib import Path
import shutil
import subprocess
import sys


def main(argv):
    output_dir, priv_dir, input_dir, npm = [Path(d).resolve() for d in argv[1:]]

    try:
        generate_runtime(output_dir, priv_dir, input_dir, npm)
    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


def generate_runtime(output_dir, priv_dir, input_dir, npm):
    priv_dir.mkdir(exist_ok=True)

    shutil.copy(input_dir / "package.json", priv_dir)
    shutil.copy(input_dir / "package-lock.json", priv_dir)

    runtime_reldir = Path("script-runtime")
    runtime_srcdir = input_dir / runtime_reldir
    runtime_intdir = priv_dir / runtime_reldir
    if runtime_intdir.exists():
        shutil.rmtree(runtime_intdir)
    shutil.copytree(runtime_srcdir, runtime_intdir)

    subprocess.run([npm, "install"], capture_output=True, cwd=priv_dir, check=True)

    shutil.copy(priv_dir / "script-runtime.js", output_dir)


if __name__ == "__main__":
    main(sys.argv)
