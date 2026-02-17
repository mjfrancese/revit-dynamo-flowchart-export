# Dynamo CPython3 - Revit 2026
# Flowchart Export v5.2 (SharePoint Lists + Parameter Extraction + Slot-Instance Classifier)
#
# CHANGELOG from v5.1:
# [4a] edge_all_types parallel tracker: records ALL observed edge types per pair
#      (edge_types still keeps single highest-rank type for pruning logic)
# [5a] EdgeKey now type-qualified: pk->ck::Type for SharePoint multi-edge uniqueness
# [7a] CSV sanitization: removed '-' from injection chars (false positives on family names)
# [8a] ParamKey collision check is now case-insensitive (matches SharePoint behavior)
# [6a] Slot-instance detector: added defensive logging for false-positive debugging
#
# CHANGELOG from v5:
# [1] DataType/Group detection reordered: ForgeTypeId first, deprecated ParameterType fallback
# [2] FamilyTypes list CSV added (FamilyKey, TypeName, LastExported) -- completes relational model
# [3] FamilyEdges now exports ALL edge types (instance/selector/repair), not just instance
# [4] Self-check / validation warnings added to OUT dict
# [5] DataTypeIdRaw diagnostic column added to FamilyParameters
# [6] Slot-instance classifier via AssociatedFamilyParameter detection
# [7] collect_parameters guard keys on (name, doc_title) to avoid name-collision dedup bugs
# [8] SharePoint file writes wrapped in per-file error handling
# [9] CSV injection sanitization on string fields
# [10] Per-family scan timestamps captured during scan_doc
# [11] ParamKey collision detection + suffix dedup
# [12] group_to_string uses GetGroupTypeId first (modern API path)
#
# Exports:
# - Main flowchart CSV:           <host>.csv
# - GraphML (from template):      <host>.graphml
# - Debug TXT (optional):         <host>.txt
# - SharePoint Lists CSVs:
#     <host>__FamilyCatalog.csv
#     <host>__FamilyEdges.csv
#     <host>__FamilyParameters.csv
#     <host>__FamilyTypes.csv      [NEW in v5.1]
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
import re
from datetime import datetime
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
    FamilySymbol,
    ExternalDefinition
)

doc = DocumentManager.Instance.CurrentDBDocument

# =============================================================================
# Inputs
# =============================================================================
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

# =============================================================================
# [9] CSV injection sanitization
# Prevents formula injection when CSVs are opened in Excel.
# Prefixes dangerous leading characters with a single quote.
# Note: '-' is intentionally excluded -- it causes false positives on family
# names and is low-risk for formula injection in CSV data cells.
# =============================================================================
_CSV_INJECTION_CHARS = ("=", "+", "@", "\t", "\r", "\n")

def sanitize_csv_value(val):
    if not isinstance(val, str):
        return val
    if val and val[0] in _CSV_INJECTION_CHARS:
        return "'" + val
    return val

# =============================================================================
# Determine output paths
# =============================================================================
if not in0 or not isinstance(in0, str) or not in0.strip():
    raise Exception("IN[0] must be a base folder path OR a full output CSV path.")

host_name = get_doc_family_name(doc)
prefix = host_name.split("-", 1)[0].strip() if "-" in host_name else host_name.strip()
if not prefix:
    prefix = "Misc"

def is_legacy_csv_path(s):
    try:
        return (s or "").strip().lower().endswith(".csv")
    except:
        return False

if is_legacy_csv_path(in0):
    output_csv = in0
    if (not output_graphml_in) or (not isinstance(output_graphml_in, str)) or (not output_graphml_in.strip()):
        base, _ = os.path.splitext(output_csv)
        output_graphml = base + ".graphml"
    else:
        output_graphml = output_graphml_in
    out_folder = os.path.dirname(output_csv)
else:
    base_folder = in0
    out_folder = os.path.join(base_folder, prefix)
    if not os.path.exists(out_folder):
        os.makedirs(out_folder)
    output_csv = os.path.join(out_folder, host_name + ".csv")
    if (not output_graphml_in) or (not isinstance(output_graphml_in, str)) or (not output_graphml_in.strip()):
        output_graphml = os.path.join(out_folder, host_name + ".graphml")
    else:
        output_graphml = output_graphml_in

if (not template_graphml) or (not isinstance(template_graphml, str)) or (not template_graphml.strip()):
    raise Exception("IN[2] must be a template GraphML path (Sample_Export_v2.graphml).")
if not os.path.exists(template_graphml):
    raise Exception("Template GraphML not found: {}".format(template_graphml))
if not doc.IsFamilyDocument:
    raise Exception("Run this from the Family Editor (a family document).")

# Overwrite guard: never allow output_graphml == template_graphml
try:
    if os.path.abspath(output_graphml).lower() == os.path.abspath(template_graphml).lower():
        raise Exception(
            "Refusing to overwrite template_graphml. Set IN[1] to a different path than IN[2]."
        )
except Exception:
    if (output_graphml or "").strip().lower() == (template_graphml or "").strip().lower():
        raise Exception(
            "Refusing to overwrite template_graphml. Set IN[1] to a different path than IN[2]."
        )

# =============================================================================
# Logging + debug txt
# =============================================================================
log = []
def safe(msg):
    if debug:
        log.append(str(msg))

def write_debug_txt(path_txt, out_dict, log_lines):
    try:
        ensure_parent_dir(path_txt)
        with open(path_txt, "w", encoding="utf-8") as f:
            f.write("=== Flowchart Export v5.2 Debug Output ===\n\n")
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

# =============================================================================
# SharePoint helpers
# =============================================================================
def to_key_slug(name):
    s = (name or "").strip().lower()
    if not s:
        return ""
    s = s.replace("+", "-plus-")
    s = re.sub(r"\s+", "-", s)
    s = re.sub(r"[^a-z0-9-]", "", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s

def TF(x):
    return "TRUE" if bool(x) else "FALSE"

def now_iso_local():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# =============================================================================
# Family helpers
# =============================================================================
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
nodes = {}
next_id = 1
edge_types = {}                          # (parent, child) -> highest-ranked single etype (for pruning)
edge_all_types = defaultdict(set)        # (parent, child) -> set of ALL observed etypes (for export)
loaded_in_candidates = defaultdict(list)
family_types_by_name = defaultdict(set)

family_param_stats = {}                  # fam -> {"count": int, "has_formulas": bool}
family_params_rows = []                  # list of dict rows for FamilyParameters CSV

# [7] Guard keys on (name, doc_title) to prevent name-collision dedup bugs
_param_collected_docs = set()            # set of (fam_name, doc_title) tuples

# [10] Per-family scan timestamps captured during scan_doc
family_scan_timestamps = {}              # fam_name -> ISO timestamp string

# [6] Slot-instance tracking
# slot_instance_children[parent_doc] = set of child family names identified as type-slot instances
slot_instance_children = defaultdict(set)

# [4] Validation warnings collected after graph construction
validation_warnings = []

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
    # Always record every observed type for export fidelity
    edge_all_types[(parent, child)].add(etype)
    # Keep highest-ranked single type for pruning/graph logic
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
# Family Types selector scan
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
# [6] Slot-instance classifier
# Detects nested instances whose "Type" element parameter is associated with a
# family parameter (i.e., the nested instance is a type-slot controlled by a
# Family Type selector, not a fixed physical placement).
#
# Uses FamilyManager.GetAssociatedFamilyParameter(elementParam) to check
# whether the instance's type selector is driven by a family-level param.
# =============================================================================
def detect_slot_instances(fam_doc, current_doc_name):
    """
    For each FamilyInstance in fam_doc, check if its type-selector element
    parameter is associated with a family parameter. If so, record the child
    family as a "slot instance" of current_doc_name.
    Returns set of child family names identified as slot instances.

    NOTE: Uses ELEM_TYPE_PARAM as the primary check. Some families may expose
    type-driven selection through other parameters -- if noisy results appear,
    validate against known slot families and consider filtering by the
    associated parameter's ForgeTypeId (should be a category-type ForgeTypeId).
    """
    fm = None
    try:
        fm = fam_doc.FamilyManager
    except:
        return set()
    if fm is None:
        return set()

    slots = set()
    try:
        insts = FilteredElementCollector(fam_doc).OfClass(FamilyInstance).ToElements()
    except:
        return set()

    for inst in insts:
        try:
            sym = inst.Symbol
            if not sym or not sym.Family:
                continue
            child_name = get_family_name_from_element(sym.Family)
            if not child_name or is_excluded_name(child_name):
                continue

            # Check if the instance's BuiltIn type parameter is associated
            # with a family-level parameter (= slot instance)
            type_param = inst.get_Parameter(BuiltInParameter.ELEM_TYPE_PARAM)
            if type_param is None:
                safe("Slot-check: no ELEM_TYPE_PARAM for {} in {}".format(child_name, current_doc_name))
                continue

            try:
                assoc = fm.GetAssociatedFamilyParameter(type_param)
            except Exception as ex_assoc:
                # GetAssociatedFamilyParameter may throw if param is not associable
                safe("Slot-check: GetAssociatedFamilyParameter threw for {} in {}: {}".format(
                    child_name, current_doc_name, ex_assoc))
                assoc = None

            if assoc is not None:
                slots.add(child_name)
                safe("Slot-instance detected: {} in {} (assoc param: {})".format(
                    child_name, current_doc_name,
                    safe_str(getattr(assoc.Definition, "Name", "?"))
                ))
        except:
            continue

    return slots

# =============================================================================
# [1] Parameter extraction and typing -- ForgeTypeId FIRST, deprecated fallback
# =============================================================================

# [12] group_to_string: GetGroupTypeId (modern) first, ParameterGroup (deprecated) fallback
def group_to_string(defn):
    # Modern path: GetGroupTypeId -> ForgeTypeId.TypeId
    try:
        g = defn.GetGroupTypeId()
        gstr = safe_str(getattr(g, "TypeId", None) or g)
        if gstr:
            return gstr
    except:
        pass
    # Deprecated fallback: ParameterGroup enum
    try:
        pg = getattr(defn, "ParameterGroup", None)
        if pg is not None:
            return safe_str(pg)
    except:
        pass
    return ""

def get_param_guid(defn):
    try:
        if isinstance(defn, ExternalDefinition):
            return safe_str(defn.GUID)
    except:
        pass
    try:
        return safe_str(getattr(defn, "GUID", None))
    except:
        return ""

def datatype_choice(defn, pname):
    """
    [1] Reordered: hardcoded overrides -> ForgeTypeId (modern) -> ParameterType (deprecated fallback).
    Returns (choice_string, raw_forge_type_id_string).
    [5] Also returns the raw ForgeTypeId for the DataTypeIdRaw diagnostic column.
    """
    pname_l = (pname or "").strip().lower()

    # --- Hardcoded overrides for known special cases ---
    if pname_l == "cost":
        return ("Currency", "")
    if pname_l == "type image":
        return ("Image", "")
    if pname_l == "analytic construction":
        return ("Other", "")

    # --- PRIMARY: ForgeTypeId via GetDataType() (Revit 2026 modern API) ---
    raw = ""
    try:
        dt = defn.GetDataType()
        raw = safe_str(getattr(dt, "TypeId", None) or dt)
    except:
        raw = ""

    dl = (raw or "").lower()
    if dl:
        if ("spec.bool" in dl) or ("boolean" in dl) or ("yesno" in dl) or ("yes/no" in dl):
            return ("Yes/No", raw)
        if ("familytype" in dl) or ("category.family" in dl) or ("family.type" in dl) or (("family" in dl) and ("type" in dl)):
            return ("Family Type", raw)
        if ("spec.material" in dl) or ("material" in dl):
            return ("Material", raw)
        if ("image" in dl) or ("spec.image" in dl):
            return ("Image", raw)
        if ("currency" in dl) or ("cost" in dl) or ("spec.currency" in dl):
            return ("Currency", raw)
        if "angle" in dl:
            return ("Angle", raw)
        if ("spec.length" in dl) or ("length" in dl) or ("distance" in dl):
            return ("Length", raw)
        if ("spec.area" in dl) or ("area" in dl):
            return ("Area", raw)
        if ("spec.volume" in dl) or ("volume" in dl):
            return ("Volume", raw)
        if ("spec.int" in dl) or ("integer" in dl) or re.search(r"(^|[^a-z])int($|[^a-z])", dl):
            return ("Integer", raw)
        if ("spec.number" in dl) or ("number" in dl) or ("double" in dl) or ("real" in dl) or ("float" in dl):
            return ("Number", raw)
        if ("spec.string" in dl) or ("string" in dl) or ("text" in dl):
            return ("Text", raw)
        # ForgeTypeId present but unrecognized -- still report it in raw column
        return ("Other", raw)

    # --- FALLBACK: deprecated ParameterType (pre-2026 compat) ---
    try:
        pt = getattr(defn, "ParameterType", None)
        if pt is not None:
            s = safe_str(pt)
            sl = s.lower()
            if ("yesno" in sl) or ("yes/no" in sl):
                return ("Yes/No", raw)
            if "integer" in sl:
                return ("Integer", raw)
            if ("number" in sl) or ("float" in sl) or ("double" in sl) or ("real" in sl):
                return ("Number", raw)
            if ("currency" in sl) or ("cost" in sl):
                return ("Currency", raw)
            if "text" in sl or "string" in sl:
                return ("Text", raw)
            if "length" in sl or "distance" in sl:
                return ("Length", raw)
            if "area" in sl:
                return ("Area", raw)
            if "volume" in sl:
                return ("Volume", raw)
            if "angle" in sl:
                return ("Angle", raw)
            if "material" in sl:
                return ("Material", raw)
            if ("familytype" in sl) or ("family type" in sl):
                return ("Family Type", raw)
            if "image" in sl:
                return ("Image", raw)
            return ("Other", raw)
    except:
        pass

    return ("Other", raw)

# =============================================================================
# Parameter collection per family document
# =============================================================================
def collect_parameters_for_family_doc(fam_doc, fam_name):
    # [7] Guard on (name, doc_title) to avoid collision when two docs share a normalized name
    doc_title = safe_str(getattr(fam_doc, "Title", ""))
    guard_key = (fam_name, doc_title)
    if guard_key in _param_collected_docs:
        return
    _param_collected_docs.add(guard_key)

    fm = None
    try:
        fm = fam_doc.FamilyManager
    except Exception as ex:
        safe("No FamilyManager for {}: {}".format(fam_name, ex))
        return
    if fm is None:
        return

    fam_key = to_key_slug(fam_name)
    if not fam_key:
        return

    count = 0
    has_formulas = False

    # [11] Track seen ParamKeys within this family to detect/handle collisions
    # [8] Case-insensitive check because SharePoint uniqueness is case-insensitive
    seen_param_keys = set()          # stores lowercased keys for collision detection

    try:
        params = list(fm.Parameters)
    except:
        params = []

    for fp in params:
        try:
            defn = fp.Definition
            pname = (safe_str(defn.Name) or "").strip()
            if not pname:
                continue

            try:
                is_instance = bool(fp.IsInstance)
            except:
                is_instance = False

            # [1] datatype_choice now returns (choice, raw_forge_id)
            data_type, raw_forge_id = datatype_choice(defn, pname)

            # [12] group_to_string uses modern API first
            group_str = group_to_string(defn)

            formula = ""
            try:
                formula = safe_str(fm.GetFormula(fp)).strip()
            except:
                try:
                    formula = safe_str(getattr(fp, "Formula", "")).strip()
                except:
                    formula = ""

            if formula:
                has_formulas = True

            try:
                is_shared = bool(fp.IsShared)
            except:
                is_shared = isinstance(defn, ExternalDefinition)

            guid = get_param_guid(defn) if is_shared else ""

            # [11] ParamKey with collision detection
            # Replace | in param name to avoid delimiter collision
            pname_safe = pname.replace("|", "/")
            param_key = fam_key + "|" + pname_safe

            # [8] Case-insensitive collision check (SharePoint uniqueness is case-insensitive)
            param_key_lower = param_key.lower()
            if param_key_lower in seen_param_keys:
                suffix = 2
                while (param_key + "__" + str(suffix)).lower() in seen_param_keys:
                    suffix += 1
                param_key = param_key + "__" + str(suffix)
                safe("ParamKey collision resolved: {} (family {})".format(param_key, fam_name))
            seen_param_keys.add(param_key.lower())

            family_params_rows.append({
                "ParamKey": param_key,
                "FamilyKey": fam_key,
                "ParamName": pname,
                "DataType": data_type,
                "DataTypeIdRaw": raw_forge_id,       # [5] new diagnostic column
                "Group": group_str,
                "Formula": formula,
                "IsShared": TF(is_shared),
                "IsInstance": TF(is_instance),
                "ParamGuid": guid
            })

            count += 1
        except Exception as ex:
            safe("Param collect skip in {}: {}".format(fam_name, ex))
            continue

    family_param_stats[fam_name] = {"count": count, "has_formulas": has_formulas}

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

    # [10] Record per-family scan timestamp
    family_scan_timestamps[current] = now_iso_local()

    try:
        owner = fam_doc.OwnerFamily
    except:
        owner = None

    ensure_node(current, owner, is_family_doc=True)

    collect_parameters_for_family_doc(fam_doc, current)
    collect_types_from_family_manager(fam_doc, current)
    collect_types_from_symbols_in_doc(fam_doc)

    # [6] Detect slot instances in this document
    try:
        slots = detect_slot_instances(fam_doc, current)
        if slots:
            slot_instance_children[current] = slots
    except:
        pass

    # Loaded families: record candidates, do NOT add edges from this alone
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

    # INSTANCE nesting edges (direct parent via SuperComponent)
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
                safe("SKIP recursion into {} from {} (not editable): {}".format(child_name, current, ex_edit))
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
# Depth & reachability
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
# Prune A: for NON-instance edges, keep only deepest parent(s) when redundant
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
# Prune B (v4 revised): dependency + rescue + profile protection + post-validation
# [6] Now also considers slot-instance classification: slot-instance edges are
# treated like selector edges for pruning (removable even if "instance" type)
# because they represent type-slot assignments, not fixed physical placements.
# =============================================================================
adj_all, rev_all = build_adjacency(edge_types)
depths = compute_depths(edge_types)

# Helper: is this edge a slot-instance edge?
# A slot-instance edge is an instance edge where the child is identified as a
# type-slot in the parent document by detect_slot_instances().
def is_slot_instance_edge(parent, child):
    return child in slot_instance_children.get(parent, set())

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

confirmed = set(candidate_justifications.keys())

# Dependency resolution: drop candidates whose justification edges would themselves be removed
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

confirmed_by_child = defaultdict(set)
for (a, child) in confirmed:
    confirmed_by_child[child].add(a)

to_remove_prune_b = set()
for child, removable_parents in confirmed_by_child.items():
    all_parents = rev_all.get(child, set())

    # Profile protection: never prune true (non-slot) instance edges into profile children
    if is_profile_name(child):
        filtered = set()
        for a in removable_parents:
            etype = edge_types.get((a, child))
            if etype != "instance":
                filtered.add(a)
            elif is_slot_instance_edge(a, child):
                # [6] Slot-instance edges into profiles ARE removable
                filtered.add(a)
            else:
                safe("Prune B KEEP (profile instance): {}->{}".format(a, child))
        removable_parents = filtered

    if not removable_parents:
        continue

    # Categorize parents: "true instance" vs "removable instance or non-instance"
    # [6] Slot-instance edges count as non-instance for rescue purposes
    instance_parents = set()
    for p in all_parents:
        etype = edge_types.get((p, child))
        if etype == "instance" and not is_slot_instance_edge(p, child):
            instance_parents.add(p)

    surviving_instance = instance_parents - removable_parents

    if surviving_instance:
        # Child retains at least one true instance parent -> safe to remove all candidates
        for a in removable_parents:
            to_remove_prune_b.add((a, child))
    else:
        # No true instance parents would survive; apply rescue logic
        # Separate into instance candidates and non-instance candidates
        instance_candidates = set()
        non_instance_candidates = set()
        for a in removable_parents:
            etype = edge_types.get((a, child))
            if etype == "instance" and not is_slot_instance_edge(a, child):
                instance_candidates.add(a)
            else:
                non_instance_candidates.add(a)

        # Remove all non-instance / slot-instance candidates
        for a in non_instance_candidates:
            to_remove_prune_b.add((a, child))

        # Rescue one instance candidate (shallowest = closest to host)
        if instance_candidates:
            sorted_inst = sorted(instance_candidates, key=lambda p: depths.get(p, 10**9))
            # Keep sorted_inst[0] (rescued), remove the rest
            for a in sorted_inst[1:]:
                to_remove_prune_b.add((a, child))

# Post-validation: reject removals whose justifications became stale
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

# Final adjacency
adj, rev = build_adjacency(edge_types)

# =============================================================================
# [4] Self-check / validation warnings
# =============================================================================
post_reachable = compute_reachable_from_hosts(edge_types)
unreachable_after = [n for n in nodes if n not in post_reachable and not nodes[n].get("is_root")]
if unreachable_after:
    validation_warnings.append("Unreachable nodes after repair: {}".format(unreachable_after))

# Check for families with no edges (potential orphans that repair connected)
orphan_candidates = [n for n in nodes if not rev.get(n) and not nodes[n].get("is_root")]
if orphan_candidates:
    validation_warnings.append("Nodes with no parent edges (root-only children): {}".format(orphan_candidates))

# Check for DataType "Other" counts to flag potential mapping gaps
other_count = sum(1 for r in family_params_rows if r.get("DataType") == "Other")
if other_count > 0:
    validation_warnings.append("{} parameters mapped to DataType 'Other' -- review DataTypeIdRaw for mapping gaps.".format(other_count))

# Log slot-instance summary
total_slots = sum(len(v) for v in slot_instance_children.values())
if total_slots > 0:
    safe("Slot-instance summary: {} slot instances detected across {} parent docs.".format(
        total_slots, len(slot_instance_children)
    ))

# =============================================================================
# Main flowchart CSV
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
# GraphML generation from template
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

for e in list(tmpl_graph.findall("g:edge", ns)):
    tmpl_graph.remove(e)
for n in list(tmpl_graph.findall("g:node", ns)):
    tmpl_graph.remove(n)

pid_to_nodeid = {r["id"]: "n{}".format(r["id"]) for r in csv_rows}

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

# =============================================================================
# SharePoint Lists export
# [3] FamilyEdges now exports ALL edge types, not just instance
# [2] FamilyTypes list CSV added
# [8] Per-file error handling
# [9] CSV injection sanitization on string fields
# [10] Per-family timestamps where available
# =============================================================================
def write_sharepoint_list_exports(folder, host_name_str, adj_dict, edge_types_dict, kind_resolver):
    batch_ts = now_iso_local()

    base = os.path.join(folder, host_name_str)
    path_catalog  = base + "__FamilyCatalog.csv"
    path_edges    = base + "__FamilyEdges.csv"
    path_params   = base + "__FamilyParameters.csv"
    path_types    = base + "__FamilyTypes.csv"           # [2] NEW

    results = {}
    system_value = prefix

    # --- FamilyCatalog ---
    try:
        ensure_parent_dir(path_catalog)
        seen_keys = set()
        catalog_rows = []
        sorted_names_local = sorted(nodes.keys(), key=lambda k: nodes[k]["id"])

        for fam_name in sorted_names_local:
            if is_excluded_name(fam_name):
                continue
            key = to_key_slug(fam_name)
            if not key or key in seen_keys:
                continue
            seen_keys.add(key)

            kind = kind_resolver(fam_name, adj_dict)

            stats = family_param_stats.get(fam_name, None)
            if stats is None:
                parameter_count = ""
                has_formulas = ""
            else:
                parameter_count = stats.get("count", "")
                has_formulas = TF(stats.get("has_formulas", False))

            # [10] Use per-family scan timestamp if available, else batch timestamp
            ts = family_scan_timestamps.get(fam_name, batch_ts)

            # [6] Flag if any slot-instance children detected from this family
            has_slots = TF(bool(slot_instance_children.get(fam_name)))

            catalog_rows.append([
                sanitize_csv_value(fam_name), key, kind, system_value, ts,
                parameter_count, has_formulas, has_slots, "Active"
            ])

        with open(path_catalog, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            # [6] Added HasSlotInstances column
            w.writerow(["FamilyName","Key","Kind","System","LastExported",
                         "ParameterCount","HasFormulas","HasSlotInstances","Status"])
            for r in catalog_rows:
                w.writerow(r)

        results["familycatalog_csv"] = path_catalog
        results["familycatalog_rows"] = len(catalog_rows)
        results["familycatalog_status"] = "ok"
    except Exception as ex:
        results["familycatalog_csv"] = path_catalog
        results["familycatalog_rows"] = 0
        results["familycatalog_status"] = "error: {}".format(ex)
        safe("FamilyCatalog write error: {}".format(ex))

    # --- FamilyEdges ---
    # [3+4] Export ALL observed edge types per pair using edge_all_types.
    # EdgeKey includes type suffix to support multi-type edges for same pair.
    # e.g., pk->ck::Instance and pk->ck::Repair can coexist.
    try:
        ensure_parent_dir(path_edges)
        edge_rows = []
        seen_edge_keys = set()

        for (parent, child), etypes_set in edge_all_types.items():
            # Only export edges that survived pruning (still in edge_types)
            if (parent, child) not in edge_types_dict:
                continue
            if is_excluded_name(parent) or is_excluded_name(child):
                continue
            pk = to_key_slug(parent)
            ck = to_key_slug(child)
            if not pk or not ck:
                continue

            # [6] Check if this is a slot-instance edge
            is_slot = is_slot_instance_edge(parent, child)

            ts = family_scan_timestamps.get(parent, batch_ts)

            for etype in sorted(etypes_set):
                # Determine label: slot overrides instance
                if etype == "instance" and is_slot:
                    edge_label = "Slot"
                else:
                    edge_label = etype.capitalize()

                # [5] Type-qualified EdgeKey for SharePoint uniqueness
                edge_key = pk + "->" + ck + "::" + edge_label
                if edge_key in seen_edge_keys:
                    continue
                seen_edge_keys.add(edge_key)
                edge_rows.append([edge_key, pk, ck, edge_label, ts])

        with open(path_edges, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["EdgeKey","ParentKey","ChildKey","EdgeType","LastExported"])
            for r in edge_rows:
                w.writerow(r)

        results["familyedges_csv"] = path_edges
        results["familyedges_rows"] = len(edge_rows)
        results["familyedges_status"] = "ok"
    except Exception as ex:
        results["familyedges_csv"] = path_edges
        results["familyedges_rows"] = 0
        results["familyedges_status"] = "error: {}".format(ex)
        safe("FamilyEdges write error: {}".format(ex))

    # --- FamilyParameters ---
    # [5] Added DataTypeIdRaw column
    # [9] CSV injection sanitization on string fields (Formula, ParamName, Group)
    try:
        ensure_parent_dir(path_params)
        with open(path_params, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ParamKey","FamilyKey","ParamName","DataType","DataTypeIdRaw",
                         "Group","Formula","IsShared","IsInstance","ParamGuid"])
            for r in sorted(family_params_rows, key=lambda x: (x["FamilyKey"], x["ParamName"])):
                w.writerow([
                    r["ParamKey"],
                    r["FamilyKey"],
                    sanitize_csv_value(r["ParamName"]),
                    r["DataType"],
                    r.get("DataTypeIdRaw", ""),
                    sanitize_csv_value(r["Group"]),
                    sanitize_csv_value(r["Formula"]),
                    r["IsShared"],
                    r["IsInstance"],
                    r["ParamGuid"]
                ])

        results["familyparameters_csv"] = path_params
        results["familyparameters_rows"] = len(family_params_rows)
        results["familyparameters_status"] = "ok"
    except Exception as ex:
        results["familyparameters_csv"] = path_params
        results["familyparameters_rows"] = 0
        results["familyparameters_status"] = "error: {}".format(ex)
        safe("FamilyParameters write error: {}".format(ex))

    # --- [2] FamilyTypes (NEW) ---
    # Exports one row per (FamilyKey, TypeName) pair for SharePoint relational completeness
    try:
        ensure_parent_dir(path_types)
        type_rows = []
        seen_type_keys = set()

        for fam_name in sorted(family_types_by_name.keys()):
            if is_excluded_name(fam_name):
                continue
            fam_key = to_key_slug(fam_name)
            if not fam_key:
                continue
            ts = family_scan_timestamps.get(fam_name, batch_ts)
            for tn in sorted(family_types_by_name[fam_name]):
                tn_stripped = (tn or "").strip()
                if not tn_stripped:
                    continue
                type_key = fam_key + "::" + to_key_slug(tn_stripped)
                if type_key in seen_type_keys:
                    continue
                seen_type_keys.add(type_key)
                type_rows.append([
                    type_key, fam_key, sanitize_csv_value(tn_stripped), ts
                ])

        with open(path_types, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["TypeKey","FamilyKey","TypeName","LastExported"])
            for r in type_rows:
                w.writerow(r)

        results["familytypes_csv"] = path_types
        results["familytypes_rows"] = len(type_rows)
        results["familytypes_status"] = "ok"
    except Exception as ex:
        results["familytypes_csv"] = path_types
        results["familytypes_rows"] = 0
        results["familytypes_status"] = "error: {}".format(ex)
        safe("FamilyTypes write error: {}".format(ex))

    return results

sp = write_sharepoint_list_exports(out_folder, host_name, adj, edge_types, determine_function)

# =============================================================================
# OUT dictionary
# =============================================================================
OUT = {
    "status": "ok",
    "version": "5.2",
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
    # [4a] Count of pairs that had multiple observed edge types before rank collapse
    "edges_with_multi_types": sum(1 for v in edge_all_types.values() if len(v) > 1),
    "prune_b_removed": len(to_remove_prune_b),
    "prune_b_invalidated": len(invalidated),
    "families_with_types": sum(1 for k, v in family_types_by_name.items() if v),
    "families_with_param_capture": len(family_param_stats),
    "slot_instances_detected": sum(len(v) for v in slot_instance_children.values()),
    "slot_instance_parent_docs": len(slot_instance_children),
    "sharepoint_exports": sp,
    "validation_warnings": validation_warnings,
    "log": log
}

if debug:
    debug_txt = os.path.splitext(output_csv)[0] + ".txt"
    wrote = write_debug_txt(debug_txt, OUT, log)
    OUT["debug_txt"] = debug_txt if wrote else None

OUT
