 - como permitir que uma autorização OIDC tenha um fallback para o OAuth2 server,
caso não seja uma requisição válida (não tem 'openid' no scope). Tem que ser
uma função/classe que permita usar em projetos oauthlib com facilidade.

 - implementar JWT para criar o ID_Token... qual seria o secret? client_secret,
talvez?

 - completar a validação de request com todos os atributos (opcionais) do spec

 - completar a criação do response... é necessária validação extra
