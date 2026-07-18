#!/bin/bash

# ==========================================
# Configuration
# ==========================================
SOURCE_DIR="${SOURCE_DIR:-./service}"        # Local directory to copy
REMOTE_USER="${REMOTE_USER:-root}"           # SSH user on the remote machines
TARGET_DIR="${TARGET_DIR:-/services}"        # Where to put the directory on the remotes
SSH_KEY="${SSH_KEY:-$HOME/.ssh}"       # SSH private key (falls back to agent/config if missing)
SSH_OPTS=(-o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
[ -f "$SSH_KEY" ] && SSH_OPTS+=(-i "$SSH_KEY")

# ==========================================
# Server List
# ==========================================
SERVERS="
167.233.219.219    team1
167.233.202.192    team2
49.13.138.183      team3
178.105.204.4      team5
178.105.156.61     team6
178.105.220.219    team7
46.224.121.36      team8
178.104.19.238     team10
46.224.38.250      team11
46.224.204.200     team13
46.224.219.85      team14
178.104.144.161    team15
78.47.79.180       team16
46.224.51.229      team18
91.98.114.176      team19
178.105.67.254     team20
188.245.61.246     team22
91.98.153.113      team23
116.203.250.138    team26
178.104.169.73     team27
116.203.251.16     team28
116.203.254.26     team31
116.203.251.23     team33
78.47.97.93        team34
188.245.204.255    team36
49.12.76.65        team38
49.12.72.217       team39
167.233.216.13     team41
188.245.59.62      team42
167.233.216.122    team43
167.233.209.126    team45
142.132.177.73     team48
167.233.220.91     team49
159.69.251.5       team51
178.105.31.89      team52
49.12.35.254       team56
116.202.100.138    team57
178.104.211.143    team58
178.104.208.140    team59
188.245.167.99     team61
188.245.164.68     team62
188.245.51.6       team63
178.105.156.128    team64
49.13.53.104       team65
167.233.236.3      team66
167.233.235.147    team69
49.13.62.13        team71
49.13.61.186       team72
188.245.58.22      team73
167.233.238.203    team74
49.13.60.92        team76
116.202.8.153      team78
168.119.187.20     team79
167.233.236.255    team80
178.105.76.152     team84
46.224.162.130     team86
168.119.55.108     team87
46.224.130.34      team88
168.119.241.169    team94
128.140.86.152     team95
91.98.155.16       team96
167.233.213.75     team99
167.233.209.40     team101
167.233.222.207    team103
167.233.222.249    team105
167.233.56.193     team106
167.233.223.63     team107
167.233.208.236    team108
91.99.234.72       team109
88.99.87.36        team110
167.233.210.91     team112
167.233.223.129    team113
167.233.202.251    team114
167.233.234.9      team115
167.233.214.164    team117
168.119.57.255     team118
188.245.53.72      team120
167.233.215.244    team122
168.119.49.167     team123
178.104.111.178    team124
168.119.57.58      team125
188.34.190.160     team126
167.233.204.173    team127
91.99.188.49       team128
91.107.210.34      team130
91.99.180.46       team131
91.99.176.159      team132
91.99.189.73       team133
91.99.185.241      team135
159.69.241.75      team138
167.233.79.206     team142
49.12.7.149        team143
162.55.163.158     team144
167.235.207.48     team145
188.245.50.209     team146
167.235.205.18     team148
167.233.224.18     team151
178.104.113.88     team152
167.233.63.13      team156
167.235.201.75     team158
167.235.199.192    team159
167.235.206.214    team160
167.235.201.235    team161
167.235.197.0      team162
88.99.38.140       team163
78.47.120.221      team164
178.105.173.152    team165
128.140.80.56      team166
188.245.53.253     team168
167.233.218.224    team171
128.140.92.109     team172
128.140.82.245     team173
128.140.83.184     team174
91.98.45.229       team175
128.140.93.92      team176
128.140.95.31      team177
88.99.12.234       team178
188.34.152.204     team179
188.34.158.101     team180
188.34.157.139     team181
138.199.238.130    team183
138.199.237.161    team184
91.98.156.8        team185
91.98.156.201      team187
49.12.215.32       team188
178.105.12.65      team189
91.98.152.68       team190
178.105.122.111    team191
167.233.234.169    team192
188.245.119.70     team193
91.99.147.216      team194
46.224.134.138     team195
167.233.215.215    team196
167.233.220.145    team198
167.233.218.73     team199
167.233.212.191    team200
167.233.226.140    team201
167.233.229.82     team202
178.105.149.82     team203
167.233.141.151    team204
49.13.127.61       team205
116.202.14.193     team206
46.224.33.190      team207
46.224.39.56       team208
178.105.0.9        team209
23.88.117.95       team211
142.132.230.51     team212
142.132.224.165    team213
142.132.228.82     team214
"

REMOTE_NAME="${REMOTE_NAME:-SignMeMaybe}"      # Directory name on the remote
REMOTE_PATH="${TARGET_DIR}/${REMOTE_NAME}"
PARALLEL="${PARALLEL:-20}"
FAILED_LOG=$(mktemp)
TARBALL=$(mktemp --suffix=.tar.gz)
trap 'rm -f "$TARBALL" "$FAILED_LOG"' EXIT

tar czf "$TARBALL" -C "$SOURCE_DIR" .

deploy() {
    local IP=$1 TEAM=$2
    # Single connection: upload tarball via stdin, extract, start build detached
    if ssh "${SSH_OPTS[@]}" "${REMOTE_USER}@${IP}" \
        "rm -rf /service ${REMOTE_PATH} && mkdir -p ${REMOTE_PATH} && tar xzf - -C ${REMOTE_PATH} && cd ${REMOTE_PATH} && { nohup sh -c 'docker compose down; for i in \$(seq 1 10); do docker compose up -d --build && break; sleep \$(shuf -i 30-120 -n 1); done' > /tmp/${REMOTE_NAME}-deploy.log 2>&1 < /dev/null & }" \
        < "$TARBALL"; then
        echo "OK  $TEAM ($IP): copied, build started"
    else
        echo "!!  $TEAM ($IP): FAILED"
        echo "$TEAM $IP" >> "$FAILED_LOG"
    fi
}

while read -r IP TEAM; do
    [ -z "$IP" ] && continue
    while [ "$(jobs -rp | wc -l)" -ge "$PARALLEL" ]; do wait -n; done
    deploy "$IP" "$TEAM" &
done <<< "$SERVERS"
wait

echo
echo "Done. $(wc -l < "$FAILED_LOG") failure(s)."
sed 's/^/  FAILED: /' "$FAILED_LOG"
