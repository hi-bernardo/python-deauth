# COMO UTILIZAR O DEAUTH

Usando o ``` airmon-ng ``` você irá colocar sua placa wifi em modo monitor com o seguinte comando:

```
sudo airmon-ng start wlan0 
```

clone o repositório e rode o script
```
git clone https://github.com/Brazoo/python-deauth.git
python3 deauth.py
```
 


### Este é apenas um projeto para facilitar a desautenticação de redes wifi
Considerei que o ``` airmon-ng ``` já está instalado em sua máquina, caso contrário instale
``` 
sudo apt update 
sudo apt install aircrack-ng
```

