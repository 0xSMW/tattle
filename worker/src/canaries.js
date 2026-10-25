// Canaries: fake credentials nobody legitimate ever uses. The worker mints
// fresh canarytokens.org tokens for one machine and returns a shell script that
// plants them in the calling user's home. Tokens report to this worker's
// /canary endpoint, and each memo names the host and file, so an alert says
// exactly which machine and which file was touched.

const CANARYTOKENS = "https://canarytokens.org/d3aece8093b71007b5ccfedad91ebb11/generate";
const MARK = "tattle-canary";

export async function mintCanaries(env, origin, where) {
	const mint = async (type, memo) => {
		const res = await fetch(CANARYTOKENS, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({
				token_type: type,
				memo: `tattle: ${where} ${memo}`,
				email: env.CANARY_EMAIL || "",
				webhook_url: `${origin}/canary?key=${env.CANARY_KEY}`,
			}),
		});
		const token = await res.json();
		if (!res.ok || token.error) throw new Error(`canarytokens ${type}: ${res.status} ${token.error_message || ""}`);
		return token;
	};
	const [aws, envFile, dns] = await Promise.all([
		mint("aws_keys", "~/.aws/credentials [backup-admin]"),
		mint("aws_keys", "~/Documents/prod-secrets.env"),
		mint("dns", "~/.ssh/config Host db-backup-prod"),
	]);
	return { aws, envFile, dns };
}

// canarytokens.org values are alphanumeric, but this text becomes a shell
// script, so strip anything else anyway.
const clean = (v) => String(v || "").replace(/[^A-Za-z0-9+/=._-]/g, "");

export function plantScript({ aws, envFile, dns }) {
	return `#!/bin/sh
# tattle canaries. Fake credentials nobody legitimate ever uses: touching them
# raises an alert. Re-running is safe: each file is planted once.
set -eu
umask 077
planted=""
mkdir -p "$HOME/.aws" "$HOME/.ssh" "$HOME/Documents"

if ! grep -qs ${MARK} "$HOME/.aws/credentials"; then
	cat >>"$HOME/.aws/credentials" <<'CANARY'

# ${MARK}: do not use
[backup-admin]
aws_access_key_id = ${clean(aws.aws_access_key_id)}
aws_secret_access_key = ${clean(aws.aws_secret_access_key)}
region = ${clean(aws.region) || "us-east-2"}
CANARY
	planted="$planted ~/.aws/credentials"
fi

if [ ! -e "$HOME/Documents/prod-secrets.env" ]; then
	cat >"$HOME/Documents/prod-secrets.env" <<'CANARY'
# production backup credentials (rotated quarterly)
AWS_ACCESS_KEY_ID=${clean(envFile.aws_access_key_id)}
AWS_SECRET_ACCESS_KEY=${clean(envFile.aws_secret_access_key)}
AWS_DEFAULT_REGION=${clean(envFile.region) || "us-east-2"}
S3_BACKUP_BUCKET=prod-db-backups
CANARY
	planted="$planted ~/Documents/prod-secrets.env"
fi

if ! grep -qs ${MARK} "$HOME/.ssh/config"; then
	cat >>"$HOME/.ssh/config" <<'CANARY'

# ${MARK}: do not use
Host db-backup-prod
  HostName ${clean(dns.hostname)}
  User root
CANARY
	chmod 600 "$HOME/.ssh/config"
	planted="$planted ~/.ssh/config"
fi

echo "tattle canaries:\${planted:- already planted}"
`;
}
