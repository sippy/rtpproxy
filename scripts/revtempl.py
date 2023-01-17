#!/usr/bin/env python3

import sys

class match():
    fromstr = int
    tostr = str
    bsym = '{'
    esym = '}'
    opos = None
    func = None
    orig = None

modfile = sys.argv[1]
datafile = sys.argv[2]

litdata = []
procs = []
data = ''
with open(modfile) as modschema:
    while True:
        _data = modschema.read()
        if not _data:
            break
        data += _data
while len(data) > 0:
    otype = match()
    otype.opos = data.find('{')
    if otype.opos == -1:
        litdata.append(data)
        data = ''
        break
    litdata.append(data[:otype.opos])
    data = data[otype.opos + 1:]
    cpos = data.find(otype.esym)
    if cpos == -1:
        raise Exception('no closing {otype.esym}')
    if cpos == 0:
        otype.func = lambda i, x, c: otype.fromstr(x)
    else:
        #print(data[:cpos])
        cmds = data[:cpos].split(';')
        cmds[-1] = F'return({cmds[-1]})'
        ftext = 'def myproc(i, x, c):\n\t' + '\n\t'.join(cmds)
        fgen = compile(ftext, "<string>", "exec")
        exec(fgen)
        otype.func = myproc
        #otype.func = eval(F'lambda i, x, c: {data[:cpos]}')
    otype.orig = data[:cpos]
    procs.append(otype)
    data = data[cpos + 1:]
#print(litdata)

data = ''
with open(datafile) as moddata:
    while True:
        _data = moddata.read()
        if not _data:
            break
        data += _data
chunks = []
for i, litchunk in enumerate(litdata):
    if not chunks:
        if not data.startswith(litchunk):
            raise Exception(F'chunk "{litchunk[:24]}...": no match')
    data = data[len(litchunk):]
    #print(data)
    if i == len(litdata) - 1:
        continue
    cpos = data.find(litdata[i + 1])
    if cpos == -1:
        #print (data)
        raise Exception(F'chunk "{litdata[i + 1]}": no match')
    #print(i, data[:cpos])
    otype = procs[i]
    chunks.append(otype.fromstr(data[:cpos]))
    data = data[cpos:]
#print(procs)
#print(chunks)
for i, x in enumerate(chunks):
    sys.stdout.write(litdata[i])
    otype = procs[i]
    try:
        result = otype.func(i, otype.fromstr(x), chunks)
    except Exception as _e:
        raise Exception(F'at chunk {otype.orig} #{i}, replacing literaldata {x}') from _e
    sys.stdout.write(otype.tostr(result))
if len(litdata) > len(chunks):
    sys.stdout.write(litdata[-1])
