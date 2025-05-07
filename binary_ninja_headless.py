import marimo

__generated_with = "0.13.6"
app = marimo.App(
    width="medium",
    layout_file="layouts/binary_ninja_headless.slides.json",
)


@app.cell
def _(mo):
    mo.md(r"""<h1>Binary Ninja Headless</h1>""")
    return


@app.cell
def _(mo):
    mo.md(r"""<h2>Marimo notebook setup</h2>""")
    return


@app.cell
def _():
    import os
    import math
    import pandas as pd
    import marimo as mo
    import sys
    from concurrent.futures import ThreadPoolExecutor
    from tqdm import tqdm
    import hashlib
    import csv
    import itertools
    from collections import Counter
    import matplotlib.pyplot as plt
    from ast import literal_eval
    import jupyter_black
    import binaryninja
    import altair as alt
    import subprocess
    import duckdb
    jupyter_black.load()

    os.environ["BN_DISABLE_USER_SETTINGS"] = "True"
    os.environ["BN_DISABLE_USER_PLUGINS"] = "True"
    os.environ["BN_DISABLE_REPOSITORY_PLUGINS"] = "True"
    return ThreadPoolExecutor, alt, binaryninja, duckdb, mo, os, pd, sys, tqdm


@app.cell
def _(mo):
    mo.md(r"""<h2>Binary Ninja version</h2>""")
    return


@app.cell
def _(binaryninja):
    binaryninja.core_version()
    return


@app.cell
def _(mo):
    mo.md(r"""<h2>Load the Binary Ninja database</h2>""")
    return


@app.cell
def _(binaryninja):
    bv = binaryninja.load("./Tenda/BNDB/trivision_webs.bndb")
    return (bv,)


@app.cell
def _(mo):
    mo.md(r"""<h2>Get the Binary Ninja Medium Level Intermediate Language Static Single Assignment (SSA) Form </h2>""")
    return


@app.cell
def _(bv):
    func = bv.get_function_at(0xB7E8)

    mlil_ssa = func.mlil.ssa_form

    for block in mlil_ssa:
        for insn in block:
            print(f"{insn.instr_index}  @  {hex(insn.address)}  {insn}")
    return (mlil_ssa,)


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""<h2>Check the def-use for the 3rd param to memcpy</h2>""")
    return


@app.cell
def _(mlil_ssa):
    mlil_ssa[25]
    return


@app.cell
def _(mlil_ssa):
    mlil_ssa[25].params[2].src
    return


@app.cell
def _(mlil_ssa):
    mlil_ssa[25].params[2].src.def_site
    return


@app.cell
def _(mlil_ssa):
    mlil_ssa[25].params[2].src.use_sites
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""<h2>Check if the 3rd param to memcpy takes negative range values</h2>""")
    return


@app.cell
def _(mlil_ssa):
    mlil_ssa[25].params[2].possible_values.ranges[0]
    return


@app.cell
def _(mlil_ssa):
    mlil_ssa[25].params[2].possible_values.ranges[0].end
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""<h2>Potentially Dangerous Calls</h2>""")
    return


@app.cell
def _(ThreadPoolExecutor, binaryninja, os, pd, sys, tqdm):
    # List of dangerous functions
    dangerous_functions = ["system", "execve", "execle", "execvp", "execlp", "doSystemCmd"]


    # Get the name of the binaries
    def get_file_name(path):
        return os.path.basename(path)


    # Get the binary architecture
    def get_architecture(bv):
        return bv.arch.name


    # Get the binary endianness
    def get_endianness(bv):
        return "Little" if bv.endianness == binaryninja.Endianness.LittleEndian else "Big"


    # Calculate the SHA256 hash of the binaries
    def get_hash(filepath):
        bv = binaryninja.load(filepath)
        t = binaryninja.transform.Transform["SHA256"]
        p = bv.parent_view
        h = t.encode(p.read(p.start, p.end))
        h_hex = h.hex()
        return h_hex


    # Calculate the cyclomatic complexity of the binaries
    def calculate_cyclomatic_complexity(function):
        edges = sum([len(block.outgoing_edges) for block in function.basic_blocks])
        nodes = len(function.basic_blocks)
        return edges - nodes + 2


    # Replaced entropy calculation function with the new implementation
    def compute_entropy(data):
        """Compute the entropy of a given byte array."""
        if not data:
            return 0.0

        from collections import Counter
        import math

        # Count the frequency of each byte value in the data
        byte_count = Counter(data)
        data_length = len(data)

        # Calculate the entropy
        entropy = 0.0
        for count in byte_count.values():
            probability = count / data_length
            entropy -= probability * math.log2(probability)

        return entropy


    # Get the segments of the binaries
    def get_seg(bv):
        segment_info = []
        for seg in bv.segments:
            segment_info.append(
                {
                    "start": seg.start,
                    "end": seg.end,
                    "readable": seg.readable,
                    "writable": seg.writable,
                    "executable": seg.executable,
                }
            )
        return segment_info


    # Get the dangerous symbols xrefs
    def find_xrefs_to_dangerous_functions(bv):
        xref_info = []

        for func_name in dangerous_functions:
            symbol = bv.get_symbol_by_raw_name(func_name)
            if symbol:
                xrefs = bv.get_code_refs(symbol.address)
                for xref in xrefs:
                    xref_info.append(
                        (func_name, hex(xref.function.start), hex(xref.address))
                    )

        return xref_info


    def analyze_binary(path):
        bv = binaryninja.load(path)

        if bv is None:
            return None, None, None, None, None, None, None, None, None, None

        ccs = []  # List to hold cyclomatic complexities

        for function in bv.functions:
            cc = calculate_cyclomatic_complexity(function)
            ccs.append(cc)

        avg_cc = sum(ccs) / len(ccs) if ccs else 0
        filename = get_file_name(path)
        file_hash = get_hash(path)
        architecture = get_architecture(bv)
        funcs = [(func.name, hex(func.start)) for func in bv.functions]
        endianness = get_endianness(bv)

        strings = [(str(string), hex(string.start)) for string in bv.get_strings()]
        segment_info = get_seg(bv)
        getrefs = find_xrefs_to_dangerous_functions(bv)

        # Read the entire binary data
        binary_data = bv.read(bv.start, bv.end - bv.start)

        # Compute the entropy of the binary data
        entropy = compute_entropy(binary_data)

        return (
            filename,
            file_hash,
            architecture,
            endianness,
            avg_cc,
            entropy,
            funcs,
            strings,
            segment_info,
            getrefs,
        )


    def analyze_directory(directory, output_file="binary_analysis_results.parquet"):
        binaries = [
            f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))
        ]

        entropies = []  # List to hold the entropy values of the binaries
        binary_data = []  # List to hold the binary data
        binary_paths = [os.path.join(directory, binary) for binary in binaries]

        # Create a process pool to analyze binaries in parallel
        print(f"Analyzing {len(binary_paths)} binaries in parallel...")

        with ThreadPoolExecutor() as executor:
            # Use tqdm to show progress
            results = list(
                tqdm(
                    executor.map(analyze_binary, binary_paths),
                    total=len(binary_paths),
                    desc="Analyzing binaries",
                )
            )

        # Process results
        for result in results:
            (
                filename,
                file_hash,
                architecture,
                endianness,
                avg_cc,
                entropy,
                funcs,
                strings,
                segment_info,
                getrefs,
            ) = result

            if filename is not None:
                entropies.append(entropy)
                binary_data.append(
                    {
                        "Binary": filename,
                        "File_Hash": file_hash,
                        "Architecture": architecture,
                        "Endianness": endianness,
                        "Average_Cyclomatic_Complexity": avg_cc,
                        "Entropy": entropy,
                        "Functions": funcs,
                        "Strings": strings,
                        "Segments": segment_info,
                        "Xrefs_to_System": getrefs,
                    }
                )

        print(f"Processed {len(binary_data)} valid binaries")
        print(f"Writing results to {output_file}")

        df = pd.DataFrame(binary_data)
        df.to_parquet(output_file, index=False)
        print("Analysis complete!")


    if __name__ == "__main__":
        # Check if running in Jupyter notebook
        try:
            # This will only be defined in Jupyter
            if "ipykernel" in sys.modules:
                print(f"Running in Jupyter notebook environment")
                # Default behavior for Jupyter
                analyze_directory("./Tenda/BNDB/")
            else:
                # Command line argument parsing for standalone script
                import argparse

                parser = argparse.ArgumentParser(
                    description="Binary analysis tool with parallel processing"
                )
                parser.add_argument(
                    "--dir",
                    type=str,
                    default="./Tenda/BNDB/",
                    help="Directory containing binaries to analyze",
                )
                parser.add_argument(
                    "--output",
                    type=str,
                    default="binary_analysis_results.parquet",
                    help="Output parquet file path",
                )

                args = parser.parse_args()

                print(f"Starting analysis of binaries in {args.dir}")
                analyze_directory(args.dir, args.output)
        except Exception as e:
            print(f"Error in argument parsing: {e}")
            # Fallback to default behavior
            print("Using default directory ./Tenda/BNDB/")
            analyze_directory("./Tenda/BNDB/")
    return


@app.cell
def _(mo):
    mo.md(r"""<h2>Load the parquet results</h2>""")
    return


@app.cell
def _(pd):
    df = pd.read_parquet("binary_analysis_results.parquet")
    return (df,)


@app.cell
def _(df):
    df
    return


@app.cell
def _(mo):
    mo.md(r"""<h2>Set the dataframe types</h2>""")
    return


@app.cell
def _(df):
    df["Strings"] = df["Strings"].astype(str)
    df["Functions"] = df["Functions"].astype(str)
    df["Binary"] = df["Binary"].astype(str)
    df["Architecture"] = df["Architecture"].astype(str)
    df["Xrefs_to_System"] = df["Xrefs_to_System"].astype(str)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""<h2>DuckDB SQL with dataframes</h2>""")
    return


@app.cell
def _(duckdb):
    duckdb.query("""
        SELECT *
        FROM df
        WHERE Entropy > 6
          AND Endianness = 'Big'
          AND Average_Cyclomatic_Complexity > 3
    """).to_df()

    return


@app.cell
def _(duckdb):
    duckdb.query("""
        SELECT *
        FROM df
        WHERE Strings LIKE '%0x8154%'
    """).to_df()
    return


@app.cell
def _(duckdb):
    duckdb.query("""
        SELECT *
        FROM df
        WHERE Functions LIKE '%0xec50%'
    """).to_df()
    return


@app.cell
def _(duckdb):
    duckdb.query("""
        SELECT *
        FROM df
        WHERE Xrefs_to_System LIKE '%0x4fb88%'
    """).to_df()
    return


@app.cell
def _(duckdb):
    duckdb.query("""
        SELECT *
        FROM df
        WHERE Average_Cyclomatic_Complexity < 3.6
    """).to_df()
    return


@app.cell
def _(mo):
    mo.md(r"""<h2>Charting with Altair</h2>""")
    return


@app.cell
def _(alt, df):
    chart3 = alt.Chart(df).mark_bar().encode(
        x=alt.X("Binary:N", sort=None, title="Binary"),
        y=alt.Y("Entropy:Q", title="Entropy"),
        color=alt.Color('Entropy:Q', scale=alt.Scale(scheme='viridis')),
        tooltip=["Binary", "Entropy"]
    ).properties(
        width=800,
        height=400,
        title="Entropy of Binaries"
    ).configure_axisX(
        labelAngle=45
    )

    chart3

    return


@app.cell
def _(alt, df):
    chart1 = alt.Chart(df).mark_bar().encode(
        x=alt.X("Binary:N", sort=None, title="Binary"),
        y=alt.Y("Average_Cyclomatic_Complexity:Q", title="Average Cyclomatic Complexity"),
        color=alt.Color('Average_Cyclomatic_Complexity:Q', scale=alt.Scale(scheme='viridis')),
        tooltip=["Binary", "Average_Cyclomatic_Complexity"]
    ).properties(
        width=800,
        height=400,
        title="Average Cyclomatic Complexity of Binaries"
    ).configure_axisX(
        labelAngle=45
    )

    chart1
    return


@app.cell
def _(duckdb):
    duckdb.query("""
        SELECT *
        FROM df
        WHERE Average_Cyclomatic_Complexity < 3.6
    """).to_df()
    return


@app.cell
def _(df):
    search_string = "system"
    df["Potential_Dangerous_Calls_To_System"] = df["Xrefs_to_System"].apply(
        lambda x: x.count(search_string)
    )
    return


@app.cell
def _(df):
    df
    return


@app.cell
def _(df):
    df_sorted = df.sort_values(by="Potential_Dangerous_Calls_To_System", ascending=False)
    return (df_sorted,)


@app.cell
def _(alt, df_sorted):
    chart2 = alt.Chart(df_sorted).mark_bar().encode(
        x=alt.X("Binary:N", title="Binary", sort=None),
        y=alt.Y("Potential_Dangerous_Calls_To_System:Q", title="Total"),
        color=alt.Color('Potential_Dangerous_Calls_To_System:Q', scale=alt.Scale(scheme='viridis')),    
        tooltip=["Binary", "Potential_Dangerous_Calls_To_System"]
    ).properties(
        width=800,
        height=400,
        title="Potential_Dangerous_Calls_To_System"
        ).configure_axisX(
        labelAngle=45
    )

    chart2
    return


@app.cell
def _(duckdb, mo):
    query = """
    SELECT *
    FROM df
    WHERE Potential_Dangerous_Calls_To_System > 200
      AND Endianness = 'Little'
      AND Average_Cyclomatic_Complexity > 6
    """

    df_filtered = duckdb.query(query).to_df()
    mo.ui.dataframe(df_filtered)

    return


@app.cell
def _(df):
    df.head()
    return


@app.cell
def _(mo):
    mo.md(r"""<h2>Interactive charting with Marimo UI slider</h2>""")
    return


@app.cell
def _(mo):
    entropy_slider = mo.ui.slider(start=0.0, stop=10.0, step=0.1, value=6.0, label="Minimum Entropy")
    entropy_slider
    return (entropy_slider,)


@app.cell
def _(alt, df, entropy_slider, mo):
    df_filtered_slider = df[df["Entropy"] > entropy_slider.value]

    chart_obj = alt.Chart(df_filtered_slider).mark_bar().encode(
        x=alt.X("Binary:N", title="Binary").scale(zero=False),
        y=alt.Y("Entropy:Q", title="Entropy").scale(zero=False),
        color=alt.Color('Entropy:Q', scale=alt.Scale(scheme='viridis')),
        tooltip=["Binary", "Entropy", "Average_Cyclomatic_Complexity"]
    ).properties(
        width=700,
        height=400,
        title="Binaries with Entropy Above Threshold"
        ).configure_axisX(
        labelAngle=45
    )

    mo.vstack([
        mo.ui.altair_chart(chart_obj)
    ])
    return


@app.cell
def _(df, pd):
    ent_chart = ["Binary", "File_Hash", "Entropy"]
    ent_chart = pd.DataFrame(df[ent_chart])
    ent_chart = ent_chart.sort_values(by=["Entropy"], ascending=False)
    ent_chart = ent_chart.reset_index(drop=True)
    return (ent_chart,)


@app.cell
def _(mo):
    mo.md(r"""<h2>Highlight results with style</h2>""")
    return


@app.cell
def _(ent_chart):
    def highlight_score(val):
        if val >= 7.0:
            return "color: red"
        else:
            return "color: green"


    ent_styled_df = ent_chart.style.map(highlight_score, subset=["Entropy"])
    ent_styled_df
    return


@app.cell
def _(mo):
    mo.md(
        r"""
    <h2>Reference Material</h2>
    - Marimo User Guide: https://docs.marimo.io/guides/
    - Marimo Examples: https://docs.marimo.io/examples/
    - Binary Ninja Python API Reference: https://api.binary.ninja/
    - Binary Ninja Intermediate Language Overview: https://docs.binary.ninja/dev/bnil-overview.html
    - Batch Processing and Other Automation Tips: https://docs.binary.ninja/dev/batch.html
    - User Informed Data Flow: https://docs.binary.ninja/dev/uidf.html
    - SSA Explained: https://carstein.github.io/2020/10/22/ssa-explained.html#fnref:1
    - Hunting Format String Vulnerabilities: https://youtu.be/Mylbm3MIiTU
    - Auditing system calls for command injection vulnerabilities using Binary Ninja's HLIL: https://youtu.be/F3uh8DuS0tE
    - cetfor/SystemCallAuditorBinja.py: https://gist.github.com/cetfor/67cbd707bf44252aebbaf6308db28ee5
    - Learning Binary Ninja for Reverse Engineering - Scripting Basics and More Part 1: https://youtu.be/RVyZBqjLrE0
    - Learning Binary Ninja for Reverse Engineering - Scripting Basics and More Part 2: https://youtu.be/gLggUUy0-iI
    """
    )
    return


if __name__ == "__main__":
    app.run()
