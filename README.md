# BACScan

## Description

The source code of *BACScan: Automatic Black-Box Detection of Broken-Access-Control Vulnerabilities in Web Applications*

```
@inproceedings{liu2025bacscan,
  title={BACScan: Automatic Black-Box Detection of Broken-Access-Control Vulnerabilities in Web Applications},
  author={Liu, Fengyu and Zhang, Yuan and Li, Enhao and Meng, Wei and Shi, Youkun and Wang, Qianheng and Wang, Chenlin and Lin, Zihan and Yang, Min},
  booktitle={Proceedings of the 2025 ACM SIGSAC Conference on Computer and Communications Security},
  pages={1320--1333},
  year={2025}
}
```

## Setup Environment

Install dependencies using [uv](https://docs.astral.sh/uv/):

```shell
uv sync
```

This will create a virtual environment and install all required dependencies.

Install Playwright browsers (Chromium):

```shell
uv run playwright install chromium
```

## Start Elasticsearch

Make sure Elasticsearch is available before crawling and scanning.

```shell
nohup ./elasticsearch > ./logs/elasticsearch_log.log 2>&1 &
```

## Configure Authentication (Token/Cookie)

Configure role cookies under `./auth/<cms>/`:

- `user`: `auth/<cms>/user_nav.json`
- `admin`: `auth/<cms>/admin_nav.json`
- `det_user`: `auth/<cms>/user_det.json` (used as attacker session in vuln detection)
- `visitor` does not require cookie/session.

## Configure Target

Edit `target.json` (array format):

```json
[
  {
    "cms": "memos",
    "url": "http://10.176.36.21:5231/",
    "role": null
  }
]
```

`role` behavior:

- `null` or omitted: run crawler with `visitor`, `user`, `admin`
- `"user"`: run crawler with `visitor` + `user`
- `"admin"`: run crawler with `visitor` + `admin`
- list form is also supported, e.g. `["visitor", "user"]`

### `target.json` demos

Run all roles for one target:

```json
[
  {
    "cms": "memos",
    "url": "http://10.176.36.21:5231/",
    "role": null
  }
]
```

Run visitor + user only:

```json
[
  {
    "cms": "memos",
    "url": "http://10.176.36.21:5231/",
    "role": "user"
  }
]
```

Run visitor + admin only:

```json
[
  {
    "cms": "memos",
    "url": "http://10.176.36.21:5231/",
    "role": "admin"
  }
]
```

Multiple targets with explicit role lists:

```json
[
  {
    "cms": "memos",
    "url": "http://10.176.36.21:5231/",
    "role": ["visitor", "user"]
  },
  {
    "cms": "xmall",
    "url": "http://10.176.36.21:8088/",
    "role": ["visitor", "admin"]
  }
]
```

## Run BACScan

Use one command only:

```shell
uv run BACScan_start.py
```

`BACScan_start.py` orchestrates the full pipeline automatically:

1. run crawler for required roles
2. merge navigation graph and build dependence
3. run vulnerability scan

## Output

- Vulnerability results: `result/`
- Navigation graphs: `vuln_detection/input/nav_graphs/`
- Data dependence construction: `vuln_detection/input/data_dependence/`

### Vulnerability results demo

CSV example (`result/result.csv`):

```csv
cms,vuln_type,attacker_role,victim_role,req_method,req,req_data
memos,horizontal,det_user,user,DELETE,http://10.176.36.21:5231/api/shortcut/215,
memos,horizontal,det_user,user,PATCH,http://10.176.36.21:5231/api/shortcut/215,"{""id"": 215, ""title"": ""AHEPUIgAFF"", ""payload"": ""[]""}"
memos,horizontal,det_user,user,GET,http://10.176.36.21:5231/?shortcutId=206
memos,vertical,det_user,admin,PATCH,http://10.176.36.21:5231/api/memo/1018,"{""id"":1018,""content"":""asaasas"",""visibility"":""PRIVATE"",""resourceIdList"":[]}"
```

### Navigation graphs demo

File location:

- `vuln_detection/input/nav_graphs/<cms>/visitor_navigraph.json`
- `vuln_detection/input/nav_graphs/<cms>/user_navigraph.json`
- `vuln_detection/input/nav_graphs/<cms>/admin_navigraph.json`

Node example:

```json
{
  "USER|GET|http://10.176.36.21:5231/|q:tag": {
    "method": "GET",
    "req_url": "http://10.176.36.21:5231/?tag=asa",
    "role": "user",
    "public": false,
    "edges": [
      "USER|GET|http://10.176.36.21:5231/|q:tag,text"
    ]
  }
}
```

### Data dependence construction demo

File location:

- `vuln_detection/input/data_dependence/<cms>.json`

Example (`operation_node -> dependent_get_nodes`):

```json
{
  "USER|POST|http://10.176.36.21:5231/api/memo|b:content,visibility|ct:json": [
    "USER|GET|http://10.176.36.21:5231/|q:tag",
    "USER|GET|http://10.176.36.21:5231/|q:text"
  ]
}
```

## NOTE

The crawling component is treated as an independent work and will be open-sourced separately. As a result, the crawler currently used in BACScan is a simplified version. For the false negatives caused by limited crawler coverage, we use `add_node.py` to manually backfill missed requests and supplement the IDDG. Usage is as follows:

1. Optional: set CMS:

```powershell
$env:BACSCAN_CMS="xmall"
```

2. Edit `add_node.py`:
- set `role` (`visitor` / `user` / `admin`)
- set `request_text` to the full raw HTTP request

3. Run:

```shell
uv run add_node.py
```
