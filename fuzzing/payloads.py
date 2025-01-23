DEFAULT_WORDLIST = [
    'api', 'v1', 'v2', 'v3', 'rest', 'graphql', 'soap',
    'auth', 'oauth', 'login', 'user', 'admin', 'test',
    'dev', 'prod', 'stage', 'beta', 'internal'
]

COMMON_PARAMETERS = {
    'id': ['1', '123', 'null', '-1'],
    'page': ['1', '0', '-1', '999999'],
    'limit': ['10', '100', '0', '-1', '999999'],
    'sort': ['asc', 'desc', 'ASC', 'DESC'],
    'filter': ['true', 'false', '1', '0'],
    'q': ['test', '*', '%', '_'],
}

CONTENT_TYPES = [
    'application/json',
    'application/xml',
    'text/plain',
    'application/x-www-form-urlencoded'
]

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']