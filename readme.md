# Autheno

Authentication and Authorization made easy

## Generate your Key 

### Linux
```bash
ssh-keygen -t rsa -P "" -b 4096 -m PEM -f jwt.key
ssh-keygen -e -m PEM -f jwtRS256.key > jwt.key.pub
```

### Windows (Powershell)
Skip the password phrase (hit enter)
```powershell
ssh-keygen -t rsa -b 4096 -m PEM -f jwt.key
ssh-keygen -e -m PEM -f jwt.key > jwt.key.pub
Get-Content .\jwt.key.pub | Set-Content -Encoding utf8 .\jwt.key.pub
```