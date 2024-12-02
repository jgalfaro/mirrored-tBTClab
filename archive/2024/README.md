#v3. Dec 2024 (python3 endianness fix)

Update

```
def build_default_tx(self, prev_tx_id, prev_out_index, value, script_pub_key, script_sig=None):
[...]
        for i in range(n_inputs):
            self.prev_tx_id.append((prev_tx_id[i])[::-1])
            self.prev_out_index.append((int2bytes(prev_out_index[i], 4))[::-1])
```

Into

```
def build_default_tx(self, prev_tx_id, prev_out_index, value, script_pub_key, script_sig=None):
[...]
        for i in range(n_inputs):
            self.prev_tx_id.append(change_endianness(prev_tx_id[i]))
            self.prev_out_index.append(change_endianness(int2bytes(prev_out_index[i], 4)))
```


Update

```
        for i in range(n_outputs):
            self.value.append((int2bytes(value[i], 8))[::-1])
            [...]
```

Into

```
        for i in range(n_outputs):
            self.value.append(change_endianness(int2bytes(value[i], 8)))
```

Update


```
def change_endianness(x):
    # If there is an odd number of elements, we make it even by adding a 0
    if (len(x) % 2) == 1:
        x += "0"
    y = x.decode('hex')
    z = y[::-1]
    return z.encode('hex')
```

Into

```
def change_endianness(x):
    decoder = codecs.getdecoder("hex_codec")
    encoder = codecs.getencoder('hex')

    # If there is an odd number of elements, we make it even by adding a 0
    if (len(x) % 2) == 1:
        x += "0"
    y = decoder(x)[0]
    aux = y[::-1]
    z = encoder(aux)
    return z[0].decode('utf-8')
```
