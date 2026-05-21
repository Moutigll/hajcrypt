# bash completion for ft_ssl

_ft_ssl_commands()
{
	echo "genrsa rsa rsautl pkeyutl \
md5 sha256 whirlpool blake2b \
base64 \
des des-ecb des-cbc des-cfb des-cfb1 des-cfb8 des-ofb des-ctr des-pcbc \
des3 des3-ecb des3-cbc des3-cfb des3-cfb1 des3-cfb8 des3-ofb des3-ctr des3-pcbc \
aes128 aes-128-ecb aes-128-cbc aes-128-cfb aes-128-cfb1 aes-128-cfb8 aes-128-ofb aes-128-ctr aes-128-pcbc \
aes192 aes-192-ecb aes-192-cbc aes-192-cfb aes-192-cfb1 aes-192-cfb8 aes-192-ofb aes-192-ctr aes-192-pcbc \
aes256 aes-256-ecb aes-256-cbc aes-256-cfb aes-256-cfb1 aes-256-cfb8 aes-256-ofb aes-256-ctr aes-256-pcbc \
blowfish blowfish-ecb blowfish-cbc blowfish-cfb blowfish-cfb1 blowfish-cfb8 blowfish-ofb blowfish-ctr blowfish-pcbc"
}

_ft_ssl_hashes()
{
	echo "md5 sha256 whirlpool blake2b"
}

_ft_ssl_ciphers()
{
	echo "des des-ecb des-cbc des-cfb des-cfb1 des-cfb8 des-ofb des-ctr des-pcbc \
des3 des3-ecb des3-cbc des3-cfb des3-cfb1 des3-cfb8 des3-ofb des3-ctr des3-pcbc \
aes128 aes-128-ecb aes-128-cbc aes-128-cfb aes-128-cfb1 aes-128-cfb8 aes-128-ofb aes-128-ctr aes-128-pcbc \
aes192 aes-192-ecb aes-192-cbc aes-192-cfb aes-192-cfb1 aes-192-cfb8 aes-192-ofb aes-192-ctr aes-192-pcbc \
aes256 aes-256-ecb aes-256-cbc aes-256-cfb aes-256-cfb1 aes-256-cfb8 aes-256-ofb aes-256-ctr aes-256-pcbc \
blowfish blowfish-ecb blowfish-cbc blowfish-cfb blowfish-cfb1 blowfish-cfb8 blowfish-ofb blowfish-ctr blowfish-pcbc"
}

_ft_ssl_hash_opts()
{
	echo "-p -q -r -s -b -h"
}

_ft_ssl_cipher_opts()
{
	echo "-p -q -s -k -e -d -i -o -a -v -h"
}

_ft_ssl_rsa_opts()
{
	echo "-I --inform \
-O --outform \
-i --in \
-o --out \
-p --passin \
-P --passout \
-t --text \
-n --noout \
-m --modulus \
-c --check \
-u --pubin \
-U --pubout \
-T --traditional \
-h --help"
}

_ft_ssl_rsautl_opts()
{
	echo "-i --in \
-o --out \
-k --inkey \
-p --passin \
-u --pubin \
-e --encrypt \
-d --decrypt \
-s --sign \
-v --verify \
-g --dgst \
-S --sigfile \
-x --hexdump \
-h --help"
}

_ft_ssl_completion()
{
	local cur
	local prev
	local cmd

	COMPREPLY=()

	cur="${COMP_WORDS[COMP_CWORD]}"
	prev="${COMP_WORDS[COMP_CWORD-1]}"
	cmd="${COMP_WORDS[1]}"

	if [[ ${COMP_CWORD} -eq 1 ]]; then
		COMPREPLY=($(compgen -W "$(_ft_ssl_commands)" -- "$cur"))
		return 0
	fi

	case "$prev" in
		-i|--in|-o|--out|-k|--inkey|-S|--sigfile)
			COMPREPLY=($(compgen -f -- "$cur"))
			return 0
			;;
		-g|--dgst)
			COMPREPLY=($(compgen -W "$(_ft_ssl_hashes)" -- "$cur"))
			return 0
			;;
		-I|--inform|-O|--outform)
			COMPREPLY=($(compgen -W "PEM" -- "$cur"))
			return 0
			;;
		--*)
			return 0
			;;
	esac

	case "$cmd" in
		md5|sha256|whirlpool|blake2b)
			COMPREPLY=($(compgen -W "$(_ft_ssl_hash_opts)" -- "$cur"))
			;;
		base64|des*|des3*|aes*|blowfish*)
			COMPREPLY=($(compgen -W "$(_ft_ssl_cipher_opts)" -- "$cur"))
			;;
		rsa)
			if [[ "$cur" == --* ]]; then
				COMPREPLY=($(compgen -W "$(
					for c in $(_ft_ssl_ciphers); do
						echo --"$c"
					done
				)" -- "$cur"))
			else
				COMPREPLY=($(compgen -W "$(_ft_ssl_rsa_opts)" -- "$cur"))
			fi
			;;
		rsautl|pkeyutl)
			COMPREPLY=($(compgen -W "$(_ft_ssl_rsautl_opts)" -- "$cur"))
			;;
		genrsa)
			COMPREPLY=($(compgen -W "-h --help" -- "$cur"))
			;;
		gendsa)
			COMPREPLY=($(compgen -W "-h --help" -- "$cur"))
			;;
		*)
			COMPREPLY=($(compgen -f -- "$cur"))
			;;
	esac
}

complete -F _ft_ssl_completion ft_ssl
