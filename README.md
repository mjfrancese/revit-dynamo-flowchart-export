# Revit Dynamo Flowchart Export

Export host-centered family nesting flowcharts from Revit Family Editor documents as CSV, yEd-compatible GraphML, and SharePoint-ready list CSVs.

## Overview

Flowchart Export v5.2 recursively scans a Revit family document (Family Editor), discovers nested family containment via `FamilyInstance.SuperComponent`, type-parameter selector relationships, and loaded-family references, then exports the resulting directed graph as:

- **CSV** with columns: Process Step ID, Process Step Description, Next Step ID, Function, Family Types
- **GraphML** compatible with [yEd Graph Editor](https://www.yworks.com/products/yed), using cloned prototype nodes from a template file
- **SharePoint Lists CSVs** (4 relational tables): FamilyCatalog, FamilyEdges, FamilyParameters, FamilyTypes

The script runs inside **Dynamo for Revit 2026** as a CPython3 node.

## Repository Structure

```
revit-dynamo-flowchart-export/
├── src/
│   ├── flowchart_export_v5_2.py  # Main Dynamo CPython3 script (current)
│   └── flowchart_export_v4.py    # Previous version (retained for reference)
├── templates/
│   └── Sample_Export_v2.graphml   # yEd template with prototype nodes/edge
├── examples/
│   └── sample_output.csv          # Example CSV output format
├── .gitignore
└── README.md
```

## Requirements

- **Revit 2026** (or compatible version with CPython3 Dynamo support)
- **Dynamo** (installed with Revit)
- **yEd Graph Editor** (free, for viewing/layouting exported GraphML files)

## Dynamo Wiring

The script expects 5 inputs wired in a Dynamo workspace:

| Port | Name | Type | Description |
|------|------|------|-------------|
| `IN[0]` | Output path | `string` | Base output folder (recommended) OR full CSV path (legacy) |
| `IN[1]` | GraphML path | `string` | Optional: explicit GraphML output path. Defaults to auto-derived. |
| `IN[2]` | Template path | `string` | Path to `Sample_Export_v2.graphml` template file |
| `IN[3]` | Include profiles | `bool` | Whether to include Profile-category families in the graph |
| `IN[4]` | Debug | `bool` | When `True`, writes a `.txt` debug artifact with full OUT JSON and log |

### Output Path Modes

**Recommended (base folder mode):** Set `IN[0]` to a folder path like `P:\Desktop\Flowcharts`. Outputs are automatically derived from the host family name:

```
P:\Desktop\Flowcharts\Door\Door-Double.csv
P:\Desktop\Flowcharts\Door\Door-Double.graphml
P:\Desktop\Flowcharts\Door\Door-Double.txt                    (if debug=True)
P:\Desktop\Flowcharts\Door\Door-Double__FamilyCatalog.csv
P:\Desktop\Flowcharts\Door\Door-Double__FamilyEdges.csv
P:\Desktop\Flowcharts\Door\Door-Double__FamilyParameters.csv
P:\Desktop\Flowcharts\Door\Door-Double__FamilyTypes.csv
```

The prefix subfolder is extracted from the family name before the first dash (e.g., `Door-Double` -> `Door`).

**Legacy mode:** Set `IN[0]` to a full `.csv` path for backward compatibility with v3 workflows.

## Exported Files

### Main Flowchart CSV

Standard flowchart with columns: `Process Step ID`, `Process Step Description`, `Next Step ID`, `Function`, `Family Types`.

### GraphML

yEd-compatible graph cloned from the template file with styled nodes per function type and directed edges.

### SharePoint Lists CSVs

Four relational CSVs designed for import into SharePoint Lists or Power Automate workflows:

| File | Key Column | Description |
|------|-----------|-------------|
| `__FamilyCatalog.csv` | `Key` | One row per family: name, kind, system, parameter stats, slot-instance flag |
| `__FamilyEdges.csv` | `EdgeKey` | One row per directed edge (type-qualified): parent/child keys, edge type, timestamp |
| `__FamilyParameters.csv` | `ParamKey` | One row per parameter per family: data type, group, formula, shared/instance flags, GUID |
| `__FamilyTypes.csv` | `TypeKey` | One row per family type name: family key, type name, timestamp |

## Algorithm Summary

### Scan Strategy

1. **Recursive family introspection** via `FilteredElementCollector(Family)` + `EditFamily` to open nested family documents
2. **Direct-parent containment** using `FamilyInstance.SuperComponent` to attach each nested instance to its direct parent (not all ancestors)
3. **Additive Family Types selector scan** probing `FamilyManager.Parameters x FamilyManager.Types` via `AsElementId` to discover families referenced through type swapping
4. **Parameter extraction** per family document via `FamilyManager.Parameters` with ForgeTypeId-first data type detection
5. **Slot-instance classification** via `FamilyManager.GetAssociatedFamilyParameter` to distinguish type-slot assignments from fixed physical placements

### Edge Types

| Type | Source | Priority |
|------|--------|----------|
| `instance` | `FamilyInstance.SuperComponent` direct parent | 4 (highest) |
| `selector` | Family Types parameter scan | 3 |
| `repair` | Host-reachability repair pass | 2 |
| `loaded` | Loaded-in candidate (not exported directly) | 1 (lowest) |

The `edge_all_types` parallel tracker records all observed edge types per pair for export fidelity, while `edge_types` keeps only the highest-ranked single type for pruning logic.

### Slot-Instance Detection

For each `FamilyInstance` in a document, the script checks whether the instance's `ELEM_TYPE_PARAM` is associated with a family-level parameter via `FamilyManager.GetAssociatedFamilyParameter()`. If associated, the child is classified as a **slot instance** (type-slot controlled by a Family Type selector) rather than a fixed physical placement. Slot-instance edges:

- Are labeled `Slot` (instead of `Instance`) in the FamilyEdges export
- Are treated as removable by Prune B (like selector edges), even if typed as `instance`
- Are flagged via `HasSlotInstances` in the FamilyCatalog

### Parameter Data Type Detection

Parameter types are resolved in priority order:

1. **Hardcoded overrides** for known special cases (`Cost` -> Currency, `Type Image` -> Image)
2. **ForgeTypeId** via `Definition.GetDataType()` (Revit 2026 modern API) -- primary path
3. **ParameterType** enum (deprecated, pre-2026 compatibility fallback)

The raw ForgeTypeId string is preserved in the `DataTypeIdRaw` column for diagnostic review.

### Repair Pass

Computes reachability from the Host node. Any unreachable node gets a `repair` edge to its deepest loaded-in parent that is already reachable. Runs iteratively (up to 12 passes) until all nodes connect to the Host.

### Pruning

**Prune A:** Among non-instance parents of a child, keep only the deepest (by BFS depth from Host) and remove shallower redundant edges.

**Prune B (v4 revised, v5.2 slot-aware):** The "directly follows" rule can remove instance edges, guarded by four phases:

1. **Candidate collection** - Identify removable edges `(A->child)` when `A->B` exists and `B` is also a parent of `child`
2. **Dependency resolution** - Drop candidates whose justification edges are themselves candidates (prevents cascading)
3. **Sole-instance rescue** - If removing all candidates would leave a child with no true instance parent, rescue the shallowest one. Slot-instance edges count as non-instance for rescue purposes.
4. **Post-validation** - Simulate all removals, rebuild adjacency, reject any removal whose justification became stale

**Profile protection:** True (non-slot) instance edges into Profile-category children are never pruned by Prune B. Slot-instance edges into profiles are removable.

### Node Functions

Each node is classified for visual styling in yEd:

| Function | Criteria |
|----------|----------|
| Host | Root family document |
| Profile | Category is "Profiles" |
| Shared Component | Family has `FAMILY_SHARED` parameter = 1 |
| Subassembly | Has children in the graph |
| Non-shared Component | Leaf node, not shared |

## GraphML Template

The template file (`templates/Sample_Export_v2.graphml`) contains prototype nodes for each Function type and one prototype edge. The script:

1. Parses the template and collects prototype nodes keyed by their `d4` (Function) data value
2. Clears the template graph
3. Clones prototypes for each exported node, updating the `y:NodeLabel` text
4. Clones the edge prototype for each relationship (direction: child -> parent in yEd)
5. Writes the result to the output GraphML path

Required prototype nodes (by `d4` value): `Host`, `Subassembly`, `Shared Component`, `Non-shared Component`, `Profile`.

## Safety Features

- **Overwrite guard**: Refuses to write GraphML output to the same path as the template file
- **CSV injection sanitization**: String fields in SharePoint CSVs are sanitized against formula injection (`=`, `+`, `@`, `\t`, `\r`, `\n` prefixes). The `-` character is intentionally excluded to avoid false positives on family names.
- **Per-file error handling**: Each SharePoint CSV write is wrapped in its own try/except so a failure in one file does not block the others
- **ParamKey collision detection**: Case-insensitive dedup with `__N` suffix to match SharePoint's case-insensitive uniqueness
- **Validation warnings**: Self-check after graph construction reports unreachable nodes, orphan candidates, and unmapped data types in the OUT dictionary
- **Debug `.txt` export**: When `debug=True`, writes OUT dictionary + log to a text file
- **Excluded families**: Three unavoidable annotation families are excluded from all processing: `Section Head - Min`, `Level Head - Upgrade`, `Section Tail - Upgrade`

## Test Results (Reference)

| Test Case | Nodes | Edges | Visited Docs | Edge Types (inst/sel/repair) | Prune B Removed | Prune B Invalidated |
|-----------|------:|------:|-------------:|------------------------------|----------------:|--------------------:|
| Wall-Panel+Stud v6 | 33 | 34 | 18 | 17 / 2 / 15 | 3 | 0 |
| Door-Double v4 | 76 | 88 | 45 | 52 / 5 / 31 | 12 | 4 |

## Version History

- **v5.2** - SharePoint Lists export (FamilyCatalog, FamilyEdges, FamilyParameters, FamilyTypes), parameter extraction with ForgeTypeId-first typing, slot-instance classifier via `GetAssociatedFamilyParameter`, parallel edge type tracking, type-qualified EdgeKeys, CSV injection sanitization, per-file error handling, ParamKey collision detection, validation warnings, per-family scan timestamps
- **v5.1** - FamilyTypes list CSV, all-edge-type export in FamilyEdges, case-insensitive ParamKey collision check, defensive slot-instance logging
- **v5** - Initial SharePoint integration, DataType/Group reordering, DataTypeIdRaw diagnostic column, slot-instance detection, collect_parameters guard keys, group_to_string modernization
- **v4** - Instance-edge pruning with safeguards, auto output paths, Family Types column, debug `.txt`, overwrite guard, profile protection
- **v3** - Direct-parent containment, selector scan, repair pass, SAFE pruning (no instance edge removal), GraphML template export
