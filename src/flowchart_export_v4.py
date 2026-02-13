# Dynamo CPython3 - Revit 2026
# Flowchart Export v4 (Auto Paths + Family Types Column)
#
# Deep recursive scan + DIRECT instance parent edges
# + ADDITIVE Family Types selector scan (does not replace instance scan)
# + Exclude unavoidable annotation families
# + Repair: no disconnected components (connect using deepest loaded-in)
# + Prune A: for NON-instance edges, keep only deepest parent(s) when redundant
# + Prune B (v4 REVISED): "directly follows" rule now CAN remove instance edges,
#   with dependency resolution to prevent cascading removals and sole-instance rescue.
# + Post-validation rejects any removal whose justification became stale.
# + Profile protection: NEVER prune INSTANCE edges into Profile children.
# + Debug TXT export: when debug=True, write a .txt next to the CSV containing OUT + log.
# + Overwrite guard: refuse to overwrite template_graphml
#
# NEW:
# - IN[0] can be a BASE FOLDER path (recommended), e.g. P:\Desktop\Flowcharts
#   Output paths will be derived automatically from current family document name:
#     base\<PrefixBeforeDash>\<FullFamilyName>.csv/.graphml/.txt
#   Example: Door-Double.rfa -> base\Door\Door-Double.csv
# - CSV includes a "Family Types" column listing known family types per family node.
#
# Inputs:
# IN[0] = base output folder (string) OR legacy full output CSV path (string ending in .csv)
# IN[1] = output GraphML full path (string, optional; defaults to computed .graphml)
# IN[2] = template GraphML full path (string)  <-- Sample_Export_v2.graphml
# IN[3] = include_profiles (bool)
# IN[4] = debug (bool)

import clr
import os
import csv
import copy
import json
import xml.etree.ElementTree as ET
from collections import deque, defaultdict

clr.AddReference("RevitServices")
from RevitServices.Persistence import DocumentManager

clr.AddReference("RevitAPI")
from Autodesk.Revit.DB import (
    BuiltInParameter,
    ElementId,
    FilteredElementCollector,
    Family,
    FamilyInstance,
    FamilySymbol
)

doc = DocumentManager.Instance.CurrentDBDocument

# -----------------------------
# Inputs
# -----------------------------
in0 = IN[0] if len(IN) > 0 else None
output_graphml_in = IN[1] if len(IN) > 1 else None
template_graphml = IN[2] if len(IN) > 2 else None
include_profiles = bool(IN[3]) if len(IN) > 3 else True
debug = bool(IN[4]) if len(IN) > 4 else False

EXCLUDE_FAMILIES = set([
    "Section Head - Min",
    "Level Head - Upgrade",
    "Section Tail - Upgrade"
])

def is_excluded_name(nm):
    return (nm or "").strip() in EXCLUDE_FAMILIES

def safe_str(x):
    try:
        return "" if x is None else str(x)
    except:
        return ""

def normalize_family_name(name):
    n = (name or "").strip()
    if n.lower().endswith(".rfa"):
        n = n[:-4]
    return n.strip()

def get_doc_family_name(fam_doc):
    return normalize_family_name(safe_str(getattr(fam_doc, "Title", ""))) or "UNKNOWN_FAMILY"

def ensure_parent_dir(path):
    d = os.path.dirname(path)
    if d and not os.path.exists(d):
        os.makedirs(d)

# -----------------------------
# Determine output paths (NEW)
# -----------------------------
if not in0 or not isinstance(in0, str) or not in0.strip():
    raise Exception("IN[0] must be a base folder path OR a full output CSV path.")

host_name = get_doc_family_name(doc)  # e.g. Door-Double
prefix = host_name.split("-", 1)[0].strip() if "-" in host_name else host_name.strip()
if not prefix:
    prefix = "Misc"

def is_legacy_csv_path(s):
    try:
        return (s or "").strip().lower().endswith(".csv")
    except:
        return False

# Legacy mode: IN[0] is full CSV path
if is_legacy_csv_path(in0):
    output_csv = in0
    if (not output_graphml_in) or (not isinstance(output_graphml_in, str)) or (not output_graphml_in.strip()):
        base, _ = os.path.splitext(output_csv)
        output_graphml = base + ".graphml"
    else:
        output_graphml = output_graphml_in
else:
    # New mode: IN[0] is base folder
    base_folder = in0
    # Create base\Prefix folder
    out_folder = os.path.join(base_folder, prefix)
    if not os.path.exists(out_folder):
        os.makedirs(out_folder)

    output_csv = os.path.join(out_folder, host_name + ".csv")

    if (not output_graphml_in) or (not isinstance(output_graphml_in, str)) or (not output_graphml_in.strip()):
        output_graphml = os.path.join(out_folder, host_name + ".graphml")
    else:
        output_graphml = output_graphml_in

# Template validation
if (not template_graphml) or (not isinstance(template_graphml, str)) or (not template_graphml.strip()):
    raise Exception("IN[2] must be a template GraphML path (Sample_Export_v2.graphml).")

if not os.path.exists(template_graphml):
    raise Exception("Template GraphML not found: {}".format(template_graphml))

if not doc.IsFamilyDocument:
    raise Exception("Run this from the Family Editor (a family document).")

# --- SAFETY: never allow overwriting the template file ---
try:
    if os.path.abspath(output_graphml).lower() == os.path.abspath(template_graphml).lower():
        raise Exception(
            "Refusing to overwrite template_graphml. "
            "Set IN[1] (output_graphml) to a different path than IN[2] (template_graphml)."
        )
except Exception:
    if (output_graphml or "").strip().lower() == (template_graphml or "").strip().lower():
        raise Exception(
            "Refusing to overwrite template_graphml. "
            "Set IN[1] (output_graphml) to a different path than IN[2] (template_graphml)."
        )

# -----------------------------
# Logging + debug txt
# -----------------------------
log = []
def safe(msg):
    if debug:
        log.append(str(msg))

def write_debug_txt(path_txt, out_dict, log_lines):
    try:
        ensure_parent_dir(path_txt)
        with open(path_txt, "w", encoding="utf-8") as f:
            f.write("=== Flowchart Export Debug Output ===\n\n")
            f.write("OUT (json):\n")
            try:
                f.write(json.dumps(out_dict, indent=2, sort_keys=True))
            except:
                f.write(repr(out_dict))
            f.write("\n\nLOG:\n")
            for line in (log_lines or []):
                f.write(str(line) + "\n")
        return True
    except Exception as ex:
        safe("Failed to write debug txt: {}".format(ex))
        return False

# -----------------------------
# Family helpers
# -----------------------------
def get_family_name_from_element(fam_elem):
    return normalize_family_name(safe_str(getattr(fam_elem, "Name", "")))

def get_family_is_shared(fam_elem):
    if fam_elem is None:
        return False
    try:
        p = fam_elem.get_Parameter(BuiltInParameter.FAMILY_SHARED)
        if p:
            return (p.AsInteger() == 1)
    except:
        pass
    try:
        return bool(fam_elem.IsShared)
    except:
        return False

def get_family_category_name(fam_elem):
    if fam_elem is None:
        return ""
    try:
        cat = fam_elem.FamilyCategory
        return safe_str(cat.Name) if cat else ""
    except:
        return ""

def is_profile_family(fam_elem):
    try:
        cat = get_family_category_name(fam_elem)
        if (cat or "").strip().lower() == "profiles":
            return True
    except:
        pass
    try:
        nm = get_family_name_from_element(fam_elem)
        return nm.lower().startswith("profile-")
    except:
        return False

# =============================================================================
# Graph model storage
# =============================================================================
nodes = {}  # name -> dict
next_id = 1

# edge_types[(parent, child)] = "instance" | "selector" | "repair" | "loaded"
edge_types = {}

# loaded-in candidates used for repair pass
loaded_in_candidates = defaultdict(list)

# NEW: family types map
# family_types_by_name["Door-Slab"] = set(["Type A", "Type B", ...])
family_types_by_name = defaultdict(set)

def record_loaded_in(child_name, parent_doc_name, depth_seen):
    if not child_name or not parent_doc_name:
        return
    if is_excluded_name(child_name) or is_excluded_name(parent_doc_name):
        return
    loaded_in_candidates[child_name].append((int(depth_seen), parent_doc_name))

def ensure_node(name, fam_elem=None, is_root=False, is_family_doc=False):
    global next_id
    if not name or is_excluded_name(name):
        return

    if name in nodes:
        if is_root:
            nodes[name]["is_root"] = True
        if is_family_doc:
            nodes[name]["is_family_doc"] = True
        if fam_elem is not None:
            nodes[name]["is_shared"] = bool(nodes[name]["is_shared"] or get_family_is_shared(fam_elem))
            if not nodes[name]["category"]:
                nodes[name]["category"] = get_family_category_name(fam_elem)
        return

    is_shared = get_family_is_shared(fam_elem) if fam_elem is not None else False
    cat = get_family_category_name(fam_elem) if fam_elem is not None else ""
    nodes[name] = {
        "id": next_id,
        "name": name,
        "is_shared": bool(is_shared),
        "category": cat,
        "is_root": bool(is_root),
        "is_family_doc": bool(is_family_doc)
    }
    next_id += 1

def add_edge(parent, child, etype):
    if not parent or not child:
        return
    if is_excluded_name(parent) or is_excluded_name(child):
        return
    if parent == child:
        return

    existing = edge_types.get((parent, child))
    rank = {"instance": 4, "selector": 3, "repair": 2, "loaded": 1}
    if existing is None or rank.get(etype, 0) > rank.get(existing, 0):
        edge_types[(parent, child)] = etype

def build_adjacency(edge_types_dict):
    adj = defaultdict(set)
    rev = defaultdict(set)
    for (p, c), t in edge_types_dict.items():
        adj[p].add(c)
        rev[c].add(p)
        adj.setdefault(c, set())
        rev.setdefault(p, set())
    return adj, rev

def determine_function(name, adj):
    n = nodes.get(name)
    if not n:
        return ""
    if n.get("is_root"):
        return "Host"
    if (n.get("category") or "").strip().lower() == "profiles":
        return "Profile"
    if bool(n.get("is_shared", False)):
        return "Shared Component"
    if len(adj.get(name, [])) > 0:
        return "Subassembly"
    return "Non-shared Component"

def is_profile_name(name):
    if not name:
        return False
    n = (name or "").strip().lower()
    if n.startswith("profile-"):
        return True
    nd = nodes.get(name, {})
    cat = (nd.get("category") or "").strip().lower()
    return cat == "profiles"

# =============================================================================
# Family Types selector scan (ADDITIVE)
# =============================================================================
def family_from_elementid(fam_doc, eid):
    try:
        if eid is None or eid == ElementId.InvalidElementId:
            return None
        el = fam_doc.GetElement(eid)
        if el is None:
            return None
        if isinstance(el, FamilySymbol):
            return el.Family
        if isinstance(el, Family):
            return el
    except:
        pass
    return None

def collect_familytype_option_families(fam_doc):
    """
    Returns set of Family elements that appear as selectable values in Family Types parameters
    across all types, by probing ElementId values.
    """
    fm = None
    try:
        fm = fam_doc.FamilyManager
    except:
        fm = None
    if fm is None:
        return set()

    try:
        fam_params = list(fm.Parameters)
        fam_types = list(fm.Types)
    except:
        return set()

    out = set()
    for fp in fam_params:
        for ft in fam_types:
            try:
                eid = ft.AsElementId(fp)
            except:
                continue
            cf = family_from_elementid(fam_doc, eid)
            if cf is None:
                continue
            out.add(cf)
    return out

# =============================================================================
# NEW: Collect family types (type names) from:
# - FamilyManager.Types for current family doc
# - FamilySymbol elements for loaded families in the doc
# =============================================================================
def collect_types_from_family_manager(fam_doc, fam_name):
    fm = None
    try:
        fm = fam_doc.FamilyManager
    except:
        fm = None
    if fm is None:
        return
    try:
        for t in list(fm.Types):
            try:
                tn = safe_str(getattr(t, "Name", "")) or safe_str(t)
                tn = (tn or "").strip()
                if tn:
                    family_types_by_name[fam_name].add(tn)
            except:
                continue
    except:
        pass

def collect_types_from_symbols_in_doc(fam_doc):
    """
    For loaded families, collect FamilySymbol.Name grouped by symbol.Family.Name
    """
    try:
        syms = FilteredElementCollector(fam_doc).OfClass(FamilySymbol).ToElements()
    except:
        syms = []
    for s in syms:
        try:
            f = s.Family
            if not f:
                continue
            fn = get_family_name_from_element(f)
            if not fn or is_excluded_name(fn):
                continue
            if (not include_profiles) and is_profile_family(f):
                continue
            tn = (safe_str(getattr(s, "Name", "")) or "").strip()
            if tn:
                family_types_by_name[fn].add(tn)
        except:
            continue

# =============================================================================
# Deep recursive scan
# =============================================================================
visited = set()

def scan_doc(fam_doc, depth):
    current = get_doc_family_name(fam_doc)
    if not current or is_excluded_name(current):
        return
    if current in visited:
        return
    visited.add(current)

    safe("Scanning doc: {} (depth {})".format(current, depth))

    try:
        owner = fam_doc.OwnerFamily
    except:
        owner = None
    ensure_node(current, owner, is_family_doc=True)

    # NEW: gather types for current doc + loaded families (symbols)
    collect_types_from_family_manager(fam_doc, current)
    collect_types_from_symbols_in_doc(fam_doc)

    # Loaded families: record loaded-in candidates; we DO NOT add edges from this alone.
    loaded = []
    try:
        fams = FilteredElementCollector(fam_doc).OfClass(Family).ToElements()
    except:
        fams = []

    for f in fams:
        try:
            nm = get_family_name_from_element(f)
            if not nm or is_excluded_name(nm):
                continue
            if (not include_profiles) and is_profile_family(f):
                continue
            ensure_node(nm, f, is_family_doc=False)
            record_loaded_in(nm, current, depth)
            loaded.append(f)
        except:
            continue

    # Instance containment edges: direct parent by SuperComponent family if present
    try:
        insts = FilteredElementCollector(fam_doc).OfClass(FamilyInstance).ToElements()
    except:
        insts = []

    for inst in insts:
        try:
            sym = inst.Symbol
            if not sym or not sym.Family:
                continue
            child_fam = sym.Family
            child_name = get_family_name_from_element(child_fam)
            if not child_name or is_excluded_name(child_name):
                continue
            if (not include_profiles) and is_profile_family(child_fam):
                continue

            parent_name = current
            parent_inst = inst.SuperComponent
            if parent_inst is not None:
                try:
                    ps = parent_inst.Symbol
                    if ps and ps.Family:
                        pn = get_family_name_from_element(ps.Family)
                        if pn and (not is_excluded_name(pn)):
                            parent_name = pn
                except:
                    parent_name = current

            ensure_node(parent_name)
            ensure_node(child_name, child_fam)
            add_edge(parent_name, child_name, "instance")

        except:
            continue

    # ADDITIVE: Family Types selector scan (doc -> option families)
    try:
        option_fams = collect_familytype_option_families(fam_doc)
    except:
        option_fams = set()

    for of in option_fams:
        try:
            on = get_family_name_from_element(of)
            if not on or is_excluded_name(on):
                continue
            if (not include_profiles) and is_profile_family(of):
                continue
            ensure_node(on, of)
            add_edge(current, on, "selector")
        except:
            continue

    # Recurse into loaded families (skip profiles + excluded)
    for f in loaded:
        try:
            child_name = get_family_name_from_element(f)
            if not child_name or is_excluded_name(child_name):
                continue
            if is_profile_family(f):
                continue
            if child_name in visited:
                continue

            try:
                nested = fam_doc.EditFamily(f)
            except Exception as ex_edit:
                safe("SKIP recursion into {} from {} (not editable): {}".format(
                    child_name, current, ex_edit))
                continue

            try:
                ensure_node(
                    get_doc_family_name(nested),
                    nested.OwnerFamily if hasattr(nested, "OwnerFamily") else None,
                    is_family_doc=True
                )
                scan_doc(nested, depth + 1)
            finally:
                try:
                    nested.Close(False)
                except:
                    pass
        except:
            continue

ensure_node(
    host_name,
    doc.OwnerFamily if hasattr(doc, "OwnerFamily") else None,
    is_root=True,
    is_family_doc=True
)
scan_doc(doc, 0)

# =============================================================================
# Depth & reachability helpers
# =============================================================================
def compute_depths(edge_types_dict):
    adj, _ = build_adjacency(edge_types_dict)
    roots = [n for n in nodes.keys() if nodes[n].get("is_root")]
    depths = {n: 10**9 for n in nodes.keys()}
    q = deque()
    for r in roots:
        depths[r] = 0
        q.append(r)
    while q:
        cur = q.popleft()
        for ch in adj.get(cur, []):
            if depths.get(ch, 10**9) > depths[cur] + 1:
                depths[ch] = depths[cur] + 1
                q.append(ch)
    return depths

def compute_reachable_from_hosts(edge_types_dict):
    adj, _ = build_adjacency(edge_types_dict)
    roots = [n for n in nodes.keys() if nodes[n].get("is_root")]
    reachable = set()
    q = deque()
    for r in roots:
        reachable.add(r)
        q.append(r)
    while q:
        cur = q.popleft()
        for ch in adj.get(cur, []):
            if ch not in reachable:
                reachable.add(ch)
                q.append(ch)
    return reachable

def pick_deepest_loaded_in_parent(child_name, reachable_set, depths):
    cands = loaded_in_candidates.get(child_name, [])
    if not cands:
        return None
    filtered = []
    for depth_seen, p in cands:
        if p in nodes and p in reachable_set:
            filtered.append((depths.get(p, 10**9), depth_seen, p))
    if not filtered:
        c2 = [(depths.get(p, 10**9), depth_seen, p) for depth_seen, p in cands if p in nodes]
        if not c2:
            return None
        c2.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
        return c2[0][2]
    filtered.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
    return filtered[0][2]

# =============================================================================
# Repair pass
# =============================================================================
max_passes = 12
for _ in range(max_passes):
    reachable = compute_reachable_from_hosts(edge_types)
    depths = compute_depths(edge_types)

    to_fix = []
    for n in nodes.keys():
        if is_excluded_name(n):
            continue
        if nodes[n].get("is_root"):
            continue
        if n not in reachable:
            to_fix.append(n)

    if not to_fix:
        break

    fixes = 0
    for n in to_fix:
        parent_doc = pick_deepest_loaded_in_parent(n, reachable, depths)
        if parent_doc and parent_doc != n:
            add_edge(parent_doc, n, "repair")
            fixes += 1

    if fixes == 0:
        break

# =============================================================================
# Prune A
# =============================================================================
depths = compute_depths(edge_types)
adj_all, rev_all = build_adjacency(edge_types)

parents_by_child = defaultdict(list)
for (p, c), t in edge_types.items():
    parents_by_child[c].append((p, t))

to_remove = set()
for child, plist in parents_by_child.items():
    non_instance = [(p, t) for (p, t) in plist if t != "instance"]
    if len(non_instance) <= 1:
        continue
    max_depth = -1
    for p, t in non_instance:
        d = depths.get(p, 10**9)
        if d != 10**9 and d > max_depth:
            max_depth = d
    if max_depth < 0:
        continue
    for p, t in non_instance:
        if depths.get(p, 10**9) < max_depth:
            to_remove.add((p, child))

for k in to_remove:
    if k in edge_types and edge_types[k] != "instance":
        del edge_types[k]

# =============================================================================
# Prune B (dependency + rescue + profile protection + post-validation)
# =============================================================================
adj_all, rev_all = build_adjacency(edge_types)
depths = compute_depths(edge_types)

candidate_justifications = {}
for child, parents in rev_all.items():
    if child not in nodes:
        continue
    if len(parents) < 2:
        continue
    parents_list = list(parents)
    for a in parents_list:
        a_kids = adj_all.get(a, set())
        if not a_kids:
            continue
        for b in parents_list:
            if a == b:
                continue
            if b in a_kids:
                key = (a, child)
                if key not in candidate_justifications:
                    candidate_justifications[key] = set()
                candidate_justifications[key].add(b)
                safe("Prune B initial candidate: {}->{}  justified by {}".format(a, child, b))

confirmed = set(candidate_justifications.keys())
max_dep_passes = 20
for dep_pass in range(max_dep_passes):
    to_drop = set()
    for (a, child) in confirmed:
        bs = candidate_justifications.get((a, child), set())
        has_valid = False
        for b in bs:
            if (a, b) in edge_types and (a, b) not in confirmed:
                has_valid = True
                break
        if not has_valid:
            to_drop.add((a, child))
    if not to_drop:
        break
    confirmed -= to_drop
    safe("Prune B dep pass {}: dropped {} weak candidates: {}".format(
        dep_pass + 1,
        len(to_drop),
        ", ".join("{}->{}".format(x, y) for (x, y) in to_drop)
    ))

confirmed_by_child = defaultdict(set)
for (a, child) in confirmed:
    confirmed_by_child[child].add(a)

to_remove_prune_b = set()
for child, removable_parents in confirmed_by_child.items():
    all_parents = rev_all.get(child, set())

    # Profile protection: never prune INSTANCE edges into profile children
    if is_profile_name(child):
        filtered = set()
        for a in removable_parents:
            if edge_types.get((a, child)) != "instance":
                filtered.add(a)
            else:
                safe("Prune B KEEP (profile instance): {}->{}".format(a, child))
        removable_parents = filtered
        if not removable_parents:
            continue

    instance_parents = set(p for p in all_parents if edge_types.get((p, child)) == "instance")
    surviving_instance = instance_parents - removable_parents

    if surviving_instance:
        for a in removable_parents:
            to_remove_prune_b.add((a, child))
            safe("Prune B REMOVE: {}->{}  (child retains instance parents: {})".format(
                a, child, surviving_instance
            ))
    else:
        instance_candidates = removable_parents & instance_parents
        non_instance_candidates = removable_parents - instance_parents

        for a in non_instance_candidates:
            to_remove_prune_b.add((a, child))
            safe("Prune B REMOVE (non-instance): {}->{}".format(a, child))

        if instance_candidates:
            sorted_inst = sorted(instance_candidates, key=lambda p: depths.get(p, 10**9))
            rescued = sorted_inst[0]
            safe("Prune B RESCUE: {}->{}  (sole instance parent protection)".format(rescued, child))
            for a in sorted_inst[1:]:
                to_remove_prune_b.add((a, child))
                safe("Prune B REMOVE (deeper instance): {}->{}".format(a, child))

# Post-validation
final_edges_check = dict(edge_types)
for k in to_remove_prune_b:
    if k in final_edges_check:
        del final_edges_check[k]

_, rev_check = build_adjacency(final_edges_check)
invalidated = set()

for (a, child) in to_remove_prune_b:
    bs = candidate_justifications.get((a, child), set())
    still_justified = False
    for b in bs:
        if (a, b) in final_edges_check and b in rev_check.get(child, set()):
            still_justified = True
            break
    if not still_justified:
        invalidated.add((a, child))
        safe("Prune B POST-VALIDATION reject: {}->{} (justification stale)".format(a, child))

to_remove_prune_b -= invalidated

for k in to_remove_prune_b:
    if k in edge_types:
        del edge_types[k]

# Final adjacency for export
adj, rev = build_adjacency(edge_types)

# =============================================================================
# CSV output (NEW COLUMN: Family Types)
# =============================================================================
ensure_parent_dir(output_csv)

sorted_names = sorted(nodes.keys(), key=lambda k: nodes[k]["id"])
csv_rows = []

with open(output_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["Process Step ID", "Process Step Description", "Next Step ID", "Function", "Family Types"])

    for name in sorted_names:
        if is_excluded_name(name):
            continue
        nid = nodes[name]["id"]

        child_ids = []
        for ch in sorted(adj.get(name, []), key=lambda x: nodes[x]["id"] if x in nodes else 10**9):
            if ch in nodes and (not is_excluded_name(ch)):
                child_ids.append(str(nodes[ch]["id"]))
        next_step = ";".join(child_ids)

        func = determine_function(name, adj)

        types_list = sorted(list(family_types_by_name.get(name, set())))
        types_str = ";".join(types_list)

        w.writerow([nid, name, next_step, func, types_str])
        csv_rows.append({"id": int(nid), "desc": name, "next": next_step, "func": func})

# =============================================================================
# GraphML generation from template (yEd classic)
# =============================================================================
NS_G = "http://graphml.graphdrawing.org/xmlns"
NS_Y = "http://www.yworks.com/xml/graphml"
ns = {"g": NS_G, "y": NS_Y}

def gtag(tag):
    return "{%s}%s" % (NS_G, tag)

tmpl_tree = ET.parse(template_graphml)
tmpl_root = tmpl_tree.getroot()
tmpl_graph = tmpl_root.find("g:graph", ns)
if tmpl_graph is None:
    raise Exception("Template GraphML has no <graph> element.")

def get_data_elem(elem, key_id):
    for d in elem.findall("g:data", ns):
        if d.get("key") == key_id:
            return d
    return None

def get_data_text(elem, key_id):
    d = get_data_elem(elem, key_id)
    return (d.text or "").strip() if d is not None and d.text else ""

def set_data_text(elem, key_id, value):
    d = get_data_elem(elem, key_id)
    if d is None:
        d = ET.SubElement(elem, gtag("data"))
        d.set("key", key_id)
    d.text = value

def set_yed_node_label_text(node_elem, text_value):
    d5 = get_data_elem(node_elem, "d5")
    if d5 is None:
        return False
    generic = d5.find("y:GenericNode", ns)
    if generic is None:
        return False
    labels = generic.findall(".//y:NodeLabel", ns)
    if not labels:
        return False
    for lab in labels:
        lab.text = text_value
    return True

# Collect prototypes (keyed by d4)
protos = {}
for n in tmpl_graph.findall("g:node", ns):
    desc = get_data_text(n, "d4")
    if desc:
        protos[desc] = copy.deepcopy(n)

required = ["Host", "Subassembly", "Shared Component", "Non-shared Component", "Profile"]
missing = [r for r in required if r not in protos]
if missing:
    raise Exception("Template missing prototype nodes with d4 exactly: {}. Missing: {}".format(
        ", ".join(required), ", ".join(missing)
    ))

edge_list = tmpl_graph.findall("g:edge", ns)
if not edge_list:
    raise Exception("Template needs at least one edge to copy edge styling.")
edge_proto = copy.deepcopy(edge_list[0])

# Clear template graph
for e in list(tmpl_graph.findall("g:edge", ns)):
    tmpl_graph.remove(e)
for n in list(tmpl_graph.findall("g:node", ns)):
    tmpl_graph.remove(n)

pid_to_nodeid = {r["id"]: "n{}".format(r["id"]) for r in csv_rows}

# Nodes
for r in sorted(csv_rows, key=lambda x: x["id"]):
    pid = r["id"]
    desc = r["desc"]
    func = r["func"]

    node_elem = copy.deepcopy(protos[func])
    node_elem.set("id", pid_to_nodeid[pid])

    ok = set_yed_node_label_text(node_elem, desc)
    if not ok:
        raise Exception("Template prototype '{}' missing y:NodeLabel under data d5.".format(func))

    set_data_text(node_elem, "d4", func)
    tmpl_graph.append(node_elem)

# Edges: child -> parent (yEd flow direction)
edge_counter = 0
for r in csv_rows:
    parent_pid = r["id"]
    parent_node_id = pid_to_nodeid[parent_pid]
    next_str = (r["next"] or "").strip()
    if not next_str:
        continue
    for part in next_str.split(";"):
        part = part.strip()
        if not part:
            continue
        try:
            child_pid = int(part)
        except:
            continue
        if child_pid not in pid_to_nodeid:
            continue

        child_node_id = pid_to_nodeid[child_pid]
        e = copy.deepcopy(edge_proto)
        e.set("id", "e{}".format(edge_counter))
        e.set("source", child_node_id)
        e.set("target", parent_node_id)

        for attr in ["sourceport", "targetport"]:
            if attr in e.attrib:
                del e.attrib[attr]

        tmpl_graph.append(e)
        edge_counter += 1

ensure_parent_dir(output_graphml)
tmpl_tree.write(output_graphml, encoding="utf-8", xml_declaration=True)

OUT = {
    "status": "ok",
    "host": host_name,
    "prefix_folder": prefix,
    "output_csv": output_csv,
    "output_graphml": output_graphml,
    "template_graphml": template_graphml,
    "include_profiles": include_profiles,
    "debug": debug,
    "node_count": len(csv_rows),
    "edge_count": edge_counter,
    "visited_docs": len(visited),
    "edges_by_type": {
        "instance": sum(1 for v in edge_types.values() if v == "instance"),
        "selector": sum(1 for v in edge_types.values() if v == "selector"),
        "repair": sum(1 for v in edge_types.values() if v == "repair")
    },
    "prune_b_removed": len(to_remove_prune_b),
    "prune_b_invalidated": len(invalidated),
    "families_with_types": sum(1 for k, v in family_types_by_name.items() if v),
    "log": log
}

if debug:
    debug_txt = os.path.splitext(output_csv)[0] + ".txt"
    wrote = write_debug_txt(debug_txt, OUT, log)
    OUT["debug_txt"] = debug_txt if wrote else None

OUT
