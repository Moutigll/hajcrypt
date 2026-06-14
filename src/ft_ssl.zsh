#compdef ft_ssl

_ft_ssl_build_command_list()
{
	local output line

	standard_cmds=(
		'list:List available groups'
		'genpkey:Generate a key pair (RSA, DSA, …)'
		'genrsa:Generate RSA private key'
		'gendsa:Generate DSA private key'
		'pkey:Public/private key management'
		'rsa:RSA key management'
		'dsa:DSA key management'
		'pkeyutl:Public key utility'
		'rsautl:RSA utility'
		'dsautl:DSA utility'
	)

	hash_cmds=()
	output="$(command ft_ssl list hashes 2>/dev/null)"
	for line in "${(@f)output}"; do
		[[ -n "$line" ]] || continue
		hash_cmds+=("$line:Message Digest command")
	done

	cipher_names=()
	cipher_cmds=()
	output="$(command ft_ssl list ciphers 2>/dev/null)"
	for line in "${(@f)output}"; do
		[[ -n "$line" ]] || continue
		cipher_names+=("$line")
		cipher_cmds+=("$line:Cipher command")
	done
}

zstyle ':completion:*:ft_ssl:*' menu select
zstyle ':completion:*' format $'\n -- \033[34m%d\033[0m --'
zstyle ':completion:*:ft_ssl:*' group-name ''
zstyle ':completion:*:ft_ssl:*' list-colors ''
zstyle ':completion:*:ft_ssl:*' file-patterns '*:all-files'
zstyle ':completion:*:ft_ssl:*' completer _complete _match _complete _list _complete

_ft_ssl_complete_commands()
{
	_describe -t standard_cmds 'Standard commands' standard_cmds
	_describe -t hash_cmds 'Message Digest commands' hash_cmds
	_describe -t cipher_cmds 'Cipher commands' cipher_cmds
}

_ft_ssl_complete_prefixed_ciphers()
{
	local -a prefixed
	local cipher

	for cipher in "${cipher_names[@]}"; do
		prefixed+=("${cipher/#/--}")
	done

	_describe -t prefixed_ciphers 'Cipher options' prefixed
}

_ft_ssl_hash_opts()
{
	_arguments \
		'-p[Read from stdin and print]' \
		'-q[Quiet mode]' \
		'-r[Reverse output format]' \
		'-b[Binary output]' \
		'-s+[String input]:string:' \
		'-h[Show help]' \
		'*:file:_files'
}

_ft_ssl_cipher_opts()
{
	_arguments \
		'-e[Encrypt mode]' \
		'-d[Decrypt mode]' \
		'-a[Base64 mode]' \
		'-p+[Password]:password:' \
		'-k+[Hex key]:hex key:' \
		'-s+[Salt]:salt:' \
		'-v+[IV]:iv:' \
		'-i+[Input file]:file:_files' \
		'-o+[Output file]:file:_files' \
		'-P[Disable padding]' \
		'-h[Show help]' \
		'*:file:_files'
}

_ft_ssl_list_opts()
{
	compadd -Q -- commands hashes ciphers
}

_ft_ssl_genrsa_opts()
{
	_arguments \
		'-o+[Output file]:file:_files' \
		'--out=[Output file]:file:_files' \
		'-p+[Password]:password:' \
		'--passout=[Password]:password:' \
		'-P+[Output public key file]:file:_files' \
		'--pubout=[Output public key file]:file:_files' \
		'-t[Use traditional PEM format (PKCS#1)]' \
		'--traditional[Use traditional PEM format (PKCS#1)]' \
		'-h[Show help]' \
		'--help[Show help]' \
		'*:key size:(1024 2048 3072 4096 8192)'

	if [[ $PREFIX == --* ]]; then
		_ft_ssl_complete_prefixed_ciphers
	fi
}

_ft_ssl_gendsa_opts()
{
	_arguments \
		'-o+[Output file]:file:_files' \
		'--out=[Output file]:file:_files' \
		'-p+[Password]:password:' \
		'--passout=[Password]:password:' \
		'-P+[Output public key file]:file:_files' \
		'--pubout=[Output public key file]:file:_files' \
		'-t[Use traditional PEM format (PKCS#1)]' \
		'--traditional[Use traditional PEM format (PKCS#1)]' \
		'-h[Show help]' \
		'--help[Show help]' \
		'*:key size:(1024 2048 3072)'

	if [[ $PREFIX == --* ]]; then
		_ft_ssl_complete_prefixed_ciphers
	fi
}

_ft_ssl_genpkey_opts()
{
	local -a key_types
	local -a sizes

	key_types=(rsa dsa)
	sizes=()

	local type=""
	if [[ ${#words} -ge 3 && ${words[3]} != -* ]]; then
		if [[ ${key_types[(r)${words[3]}]} == ${words[3]} ]]; then
			type=${words[3]}
		fi
	fi

	if [[ $CURRENT -eq 3 && -z $type ]]; then
		compadd -a key_types
		return
	fi

	if [[ $type == rsa ]]; then
		sizes=(1024 2048 3072 4096 8192)
	elif [[ $type == dsa ]]; then
		sizes=(1024 2048 3072)
	fi

	_arguments \
		'-o+[Output file]:file:_files' \
		'--out=[Output file]:file:_files' \
		'-p+[Password]:password:' \
		'--passout=[Password]:password:' \
		'-P+[Output public key file]:file:_files' \
		'--pubout=[Output public key file]:file:_files' \
		'-t[Use traditional PEM format]' \
		'--traditional[Use traditional PEM format]' \
		'-h[Show help]' \
		'--help[Show help]' \
		"*:key size:(${sizes[*]})"

	if [[ $PREFIX == --* ]]; then
		_ft_ssl_complete_prefixed_ciphers
	fi
}

_ft_ssl_rsa_opts()
{
	_arguments \
		'-I+[Input format]:format:(PEM)' \
		'--inform=[Input format]:format:(PEM)' \
		'-O+[Output format]:format:(PEM)' \
		'--outform=[Output format]:format:(PEM)' \
		'-i+[Input file]:file:_files' \
		'--in=[Input file]:file:_files' \
		'-o+[Output file]:file:_files' \
		'--out=[Output file]:file:_files' \
		'-p+[Input password]:password:' \
		'--passin=[Input password]:password:' \
		'-P+[Output password]:password:' \
		'--passout=[Output password]:password:' \
		'-t[Print text]' \
		'--text[Print text]' \
		'-n[No output]' \
		'--noout[No output]' \
		'-m[Print modulus]' \
		'--modulus[Print modulus]' \
		'-c[Check key]' \
		'--check[Check key]' \
		'-u[Public key input]' \
		'--pubin[Public key input]' \
		'-U[Public key output]' \
		'--pubout[Public key output]' \
		'-T[Traditional PEM]' \
		'--traditional[Traditional PEM]' \
		'-h[Show help]' \
		'--help[Show help]' \
		'*:file:_files'

	if [[ $PREFIX == --* ]]; then
		_ft_ssl_complete_prefixed_ciphers
	fi
}

_ft_ssl_dsa_opts()
{
	_arguments \
		'-I+[Input format]:format:(PEM)' \
		'--inform=[Input format]:format:(PEM)' \
		'-O+[Output format]:format:(PEM)' \
		'--outform=[Output format]:format:(PEM)' \
		'-i+[Input file]:file:_files' \
		'--in=[Input file]:file:_files' \
		'-o+[Output file]:file:_files' \
		'--out=[Output file]:file:_files' \
		'-p+[Input password]:password:' \
		'--passin=[Input password]:password:' \
		'-P+[Output password]:password:' \
		'--passout=[Output password]:password:' \
		'-t[Print text]' \
		'--text[Print text]' \
		'-n[No output]' \
		'--noout[No output]' \
		'-m[Print modulus (RSA only)]' \
		'--modulus[Print modulus (RSA only)]' \
		'-c[Check key]' \
		'--check[Check key]' \
		'-u[Public key input]' \
		'--pubin[Public key input]' \
		'-U[Public key output]' \
		'--pubout[Public key output]' \
		'-T[Traditional PEM]' \
		'--traditional[Traditional PEM]' \
		'-h[Show help]' \
		'--help[Show help]' \
		'*:file:_files'

	if [[ $PREFIX == --* ]]; then
		_ft_ssl_complete_prefixed_ciphers
	fi
}

_ft_ssl_pkey_opts()
{
	local -a key_types
	key_types=(rsa dsa)

	# First positional argument (after "pkey") should be the key type
	if [[ $CURRENT -eq 3 && $words[2] == pkey && -z $words[3] ]]; then
		compadd -a key_types
		return
	fi

	# Otherwise show the common key management options
	_arguments \
		'-I+[Input format]:format:(PEM)' \
		'--inform=[Input format]:format:(PEM)' \
		'-O+[Output format]:format:(PEM)' \
		'--outform=[Output format]:format:(PEM)' \
		'-i+[Input file]:file:_files' \
		'--in=[Input file]:file:_files' \
		'-o+[Output file]:file:_files' \
		'--out=[Output file]:file:_files' \
		'-p+[Input password]:password:' \
		'--passin=[Input password]:password:' \
		'-P+[Output password]:password:' \
		'--passout=[Output password]:password:' \
		'-t[Print text]' \
		'--text[Print text]' \
		'-n[No output]' \
		'--noout[No output]' \
		'-m[Print modulus (RSA only)]' \
		'--modulus[Print modulus (RSA only)]' \
		'-c[Check key]' \
		'--check[Check key]' \
		'-u[Public key input]' \
		'--pubin[Public key input]' \
		'-U[Public key output]' \
		'--pubout[Public key output]' \
		'-T[Traditional PEM]' \
		'--traditional[Traditional PEM]' \
		'-h[Show help]' \
		'--help[Show help]' \
		'*:file:_files'

	if [[ $PREFIX == --* ]]; then
		_ft_ssl_complete_prefixed_ciphers
	fi
}

_ft_ssl_rsautl_opts()
{
	_arguments \
		'-i+[Input file]:file:_files' \
		'--in=[Input file]:file:_files' \
		'-o+[Output file]:file:_files' \
		'--out=[Output file]:file:_files' \
		'-k+[Key file]:file:_files' \
		'--inkey=[Key file]:file:_files' \
		'-p+[Password]:password:' \
		'--passin=[Password]:password:' \
		'-u[Public key input]' \
		'--pubin[Public key input]' \
		'-e[Encrypt]' \
		'--encrypt[Encrypt]' \
		'-d[Decrypt]' \
		'--decrypt[Decrypt]' \
		'-s[Sign]' \
		'--sign[Sign]' \
		'-v[Verify]' \
		'--verify[Verify]' \
		'-g+[Digest algorithm]:digest:(md5 sha256 sha384 sha512)' \
		'--dgst=[Digest algorithm]:digest:(md5 sha256 sha384 sha512)' \
		'-S+[Signature file]:file:_files' \
		'--sigfile=[Signature file]:file:_files' \
		'-x[Hexdump output]' \
		'--hexdump[Hexdump output]' \
		'-H[Hash input instead of binary]' \
		'--hashe[Hash input instead of binary]' \
		'-h[Show help]' \
		'--help[Show help]' \
		'*:file:_files'
}

_ft_ssl_build_command_list

if (( CURRENT == 2 )); then
	_ft_ssl_complete_commands
	return
fi

cmd="${words[2]}"

case "$cmd" in
	list)
		_ft_ssl_list_opts
		;;
	md5|sha256|whirlpool|blake2b)
		_ft_ssl_hash_opts
		;;
	rsa)
		_ft_ssl_rsa_opts
		;;
	dsa)
		_ft_ssl_dsa_opts
		;;
	pkey)
		_ft_ssl_pkey_opts
		;;
	genrsa)
		_ft_ssl_genrsa_opts
		;;
	gendsa)
		_ft_ssl_gendsa_opts
		;;
	genpkey)
		_ft_ssl_genpkey_opts
		;;
	rsautl|pkeyutl|dsautl)
		_ft_ssl_rsautl_opts
		;;
	*)
		_ft_ssl_cipher_opts
		;;
esac
