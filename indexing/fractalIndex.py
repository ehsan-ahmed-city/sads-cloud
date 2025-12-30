from __future__ import annotations
from dataclasses import dataclass
#added for data-olny classes
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
#for timestamping index and maybe for logs


@dataclass
class FitIndex:

    
    """
    fractal index tree(FIT) representation as a hierarcical json
    root-> files->clusters -> block_keys
    tree-structured index and support fast lookup (filename,cluster_id)
    """
    user_id: str #cog id
    created_ts_utc: str


    files: Dict[str, Dict[str, Dict[str, List[str]]]]#ilename -> clusters:{cluster id: keys]} for tree

    def to_dict(self) -> Dict[str, Any]:
        #creating function to change python obj into json dict before uploads to s3


        return {
            "user_id": self.user_id,
            "created_ts_utc": self.created_ts_utc,
            "files": self.files,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "FitIndex":
        #reversing so from fit json to obj

        return FitIndex(
            user_id=d["user_id"],
            created_ts_utc=d.get("created_ts_utc", ""),
            files=d.get("files", {}),
        )


def buildFitClustSummary(cluster_summary: Dict[str, Any]) -> FitIndex:
    """
    function so input:clusters.json, Output a FIT index object with file ->cluster-> keys
    clusters.json sort groups by cluster_id only, block keys contain filename so we extract filename from each key path
    """
    user_id = cluster_summary["user_id"]
    created = datetime.now(timezone.utc).isoformat()
    #getting user and timestamp

    #buildign the tree
    files: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
    clusters: Dict[str, List[str]] = cluster_summary.get("clusters", {})

    for cluster_id, keys in clusters.items():#for loop on clusters and keys
        for k in keys:
            #for loop to get filename from k, k is like encrypted/user_id/filename/block_00000
            parts = k.split("/")
            filename = parts[2] if len(parts) >= 4 else "unknown"

            files.setdefault(filename, {"clusters": {}})
            files[filename]["clusters"].setdefault(cluster_id, [])
            files[filename]["clusters"][cluster_id].append(k)
            #making the dtree^

    # Sort block keys within each cluster so retrieval is deterministic
    for fname in files:
        for cid in files[fname]["clusters"]:
            files[fname]["clusters"][cid] = sorted(files[fname]["clusters"][cid])#for loop to sort blocks that are retireved so there's no corruptio or artifacts

    return FitIndex(user_id=user_id, created_ts_utc=created, files=files)


def lookup(
    #func to query index
    fit: FitIndex,
    filename: Optional[str] = None,
    cluster_id: Optional[str] = None,
) -> List[str]:
    """
    lookup keys in the FIT

    supports filename only, returns all block keys for that file, filename +cluster_id:returns only keys in that cluster
    ,cluster_id only: returns keys across all files for that cluster
    """
    results: List[str] = []

    if filename and filename in fit.files:
        clusters = fit.files[filename]["clusters"]
        #filename and cluster as one case
        if cluster_id:
            return list(clusters.get(cluster_id, [])) #returns block for thie file
        
        for cid, ks in clusters.items():
            #filename only for another case
            results.extend(ks)
        return sorted(results)

    if cluster_id:
        #cluster only as another case
        for fname, node in fit.files.items():
            results.extend(node["clusters"].get(cluster_id, []))
        return sorted(results)

    # no filters = return everything
    for fname, node in fit.files.items():
        for cid, ks in node["clusters"].items():
            results.extend(ks)
    return sorted(results)