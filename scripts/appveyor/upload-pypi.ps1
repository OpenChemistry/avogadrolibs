trap { Write-Error $_; Exit 1 }

pip install twine
twine upload dist/*
