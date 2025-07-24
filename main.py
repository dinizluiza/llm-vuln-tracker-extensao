def getDepenTxt(file_path):
    names = []
    versions = []
    with open(file_path, 'r') as file:
        for line in file:
            equalPos = line.index('=')
            names.append(line[:equalPos])
            version = line[equalPos+2:].strip()
            versions.append(version)
    return names, versions

def txtOrjson(file_path):
    dotPos = file_path.index('.')
    extension = file_path[dotPos+1:]
    #print(extension)
    return extension

def main():
    file_path = input("Escreva o caminho para seu arquivo de dependências: ")
    extension = txtOrjson(file_path)
    #content = getContent(file_path)
    #n_lines = countLines(file_path)
    if extension == 'txt':
        names, versions = getDepenTxt(file_path)
        print(names,'\n',versions)
    else:
        print('Extensão não aceita!')


if __name__ == '__main__':
    main()