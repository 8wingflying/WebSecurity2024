Python  Flask Web從入門到實戰配套資源

#  章節實例源碼
#  ch2
#  2-1
## app.py
``` Python
# 從flask框架中導入Flask類
from flask import Flask
# 傳入__name__初始化一個Flask實例
app = Flask(__name__)
#這個路由將根URL映射到了hello_world函數上
@app.route('/')
def hello_world():
    return 'Hello World!'
if __name__ == '__main__':
    #指定預設主機為是127.0.0.1，port為8888
    app.run(debug=True,host='0.0.0.0', port=8888)
```
#  2-2
## app.py
``` Python
#encoding:utf-8
from flask import Flask
app = Flask(__name__)
@app.route('/')
def hello_world():
    return '這是url傳參演示!'
@app.route('/user/<name>')
def list_name(name):
    return "接收到的名字為： %s" % name
@app.route('/news/<int:id>')
def list_news(id):
    return "接收到的id為： %s" % id
if __name__ == '__main__':
    app.run(debug=True)
```
#  2-3
## app.py
``` Python
# encoding: utf-8
from flask import Flask,url_for
app = Flask(__name__)
@app.route("/")
def index():
    url1=(url_for('news', id='10086'))
    print(url_for('index'))
    return "URL反轉內容為：%s" % url1
@app.route('/news/<id>')
def news(id):
    return u'您請求的參數是:%s' %id
if __name__ == '__main__':
    app.run(debug=True)
```
#  2-4
## app.py
``` Python
#endoding:utf-8
from flask import Flask,url_for,redirect
app = Flask(__name__)
@app.route('/')
def hello_world():
    print("首先訪問了index()這個視圖函數了！")
    url1=url_for('user_login')
    return redirect(url1)
@app.route('/user_login')
def user_login():
    return "這是使用者登錄頁面，請您登錄,才能訪問首頁！"
if __name__ == '__main__':
    app.run()
```


#  ch3
#  3-1
## app.py
``` Python
from flask import Flask
from flask import render_template
app = Flask(__name__)
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/user/')
def user():
    return render_template('user.html')
if __name__ == '__main__':
    app.run(debug=True)
```
#  3-2
## app.py
``` Python
from flask import Flask
from flask import render_template
app = Flask(__name__)
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/user/<username>')
def user(username):
    return render_template('user.html', name=username)
if __name__ == '__main__':
    app.run(debug=True)
```
#  3-3
## app.py
``` Python
#encoding:utf-8
from flask import Flask,render_template#導入Flask以及render_template 模組
import random#導入random模組
app = Flask(__name__)#Flask初始化
@app.route('/') #定義路由
def hello_world():#定義視圖函數
       rand1=random.randint(0,1)# 產生0-1範圍內的整型數
       return render_template('index.html',name=rand1)#渲染範本，並向範本傳遞值
if __name__ == '__main__': #當模組被直接運行時，代碼將被運行，當模組是被導入時，代碼不被執行
       app.run(debug=True)#開啟調試模式
```
#  3-4
## app.py
``` Python
#encoding:utf-8
from flask import Flask,render_template#導入Flask以及render_template 模組
import random#導入random模組
app = Flask(__name__)#Flask初始化
@app.route('/') #定義路由
def hello_world():#定義視圖函數
       rand1=random.randint(0,3)# 產生0-3範圍內的整型數
       return render_template('index.html',name=rand1)#渲染範本，並向範本傳遞值
if __name__ == '__main__': #當模組被直接運行時，代碼將被運行，當模組是被導入時，代碼不被執行
       app.run(debug=True)#開啟調試模式
```
#  3-5
## app.py
``` Python
#encoding:utf-8
from flask import Flask,render_template#導入Flask以及render_temlate模組
app = Flask(__name__)#Flask模組初始化
@app.route('/')#定義路由
def hello_world():#定義視圖函數
       goods = [{'name': '怪味少女開衫外套春秋韓版學生bf原宿寬鬆運動風2018新款秋裝上衣',  'price': 138.00},
                {'name': 'A7seven 復古百搭牛仔外套女秋季2018新款寬鬆顯瘦休閒夾克衫上衣',  'price': 100.00},
                {'name': '黑色時尚西裝外套女春秋中長款2018新款韓版休閒薄款chic西服上衣', 'price': 100.00},
                {'name': 'HAVE RICE飯館 顏值超耐打 復古牛仔外套女短款 2018春秋新款上衣', 'price': 129.00}
               ]#定義列表goods
       return render_template('shop.html', **locals())#渲染範本，並向範本傳遞參數
if __name__ == '__main__':#模組可以直接運行
       app.run()
```
#  3-6
## app.py
``` Python
#encoding:utf-8
from flask import Flask,render_template#導入Flask以及render_template模組
app = Flask(__name__)#Flask初始化
@app.route('/')#定義路由
def hello_world():#定義視圖函數
     student={#定義字典
         "name":"wangjie",
         "age":-18
     }
     return render_template('index.html',**student)#渲染範本，並向範本傳遞值
if __name__ == '__main__':
     app.run()



```
#  3-7
## app.py
``` Python
#encoding:utf-8
import sys#導入sys模組
from flask import Flask,render_template#導入Flask和render_template模組
app = Flask(__name__)#Flask初始化
@app.route('/')#定義路由
 #視圖函數
def hello_world():
     goods = [{'name': '怪味少女開衫外套春秋韓版學生bf原宿寬鬆運動風2018新款秋裝上衣'},
              {'name': 'A7seven 復古百搭牛仔外套女秋季2018新款寬鬆顯瘦休閒夾克衫上衣'},
              {'name': '黑色時尚西裝外套女春秋中長款2018新款韓版休閒薄款chic西服上衣'},
              {'name': 'HAVE RICE飯館 顏值超耐打 復古牛仔外套女短款 2018春秋新款上衣'}
              ]#定義列表goods
     return render_template('index.html',**locals())#渲染範本，並向範本傳遞值
def do_index_class(index):#定義函數
     if index % 3==0:#每間隔3行輸出line
         return 'line'
     else:
         return ''
app.add_template_filter(do_index_class, 'index_class')#使用自訂篩檢程式添加css
if __name__ == '__main__':
    app.run()




```
#  3-8
## app.py
``` Python
from flask import Flask,render_template
app = Flask(__name__)
@app.route('/')
def hello_world():
    return render_template('index.html')
if __name__ == '__main__':
    app.run(debug=True)
```
#  3-9
## app.py
``` Python
from flask import Flask,render_template
app = Flask(__name__)
@app.route('/')
def hello_world():
    return render_template('index.html')
if __name__ == '__main__':
    app.run()
```
#  3-10
## app.py
``` Python
from flask import Flask,render_template
app = Flask(__name__)
@app.route('/')
def hello_world():
    return render_template('index.html')
if __name__ == '__main__':
    app.run()
```
#  3-11
## app.py
``` Python
from flask import Flask,render_template
app = Flask(__name__)
@app.route('/')
def hello_world():
    return render_template('index.html')
if __name__ == '__main__':
    app.run(debug=True)
```
#  3-12
## app.py
``` Python
from flask import Flask,render_template
app = Flask(__name__)
@app.route('/')
def hello_world():
    return render_template('index.html')
if __name__ == '__main__':
    app.run()
```
#  3-13
## app.py
``` Python
from flask import Flask,render_template
app = Flask(__name__)
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/product')
def product():
    return render_template('product.html')
if __name__ == '__main__':
    app.run(debug=True)
```
