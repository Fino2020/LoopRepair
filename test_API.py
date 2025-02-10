# encoding: utf-8
# @File  : test_API.py
# @Author: Yzl
# @Desc : 
# @Date  :  2025/01/10

import openai

openai.api_key = "sk-EB6KoO8Pq4ZRycbefzGYM9M07DVJXSUzjYUJBd71OXK4cmv7"
openai.base_url = 'https://chatapi.onechats.top/v1/'


# f3 = open("./gpt3.5.response.txt", "w+", encoding="utf-8", errors="ignore")
def get_response(question):
    response = openai.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are now playing the role of a vulnerability repair expert."},
            {"role": "user", "content": question},
        ],
    )
    text = response.choices[0].message.content
    return text


if __name__ == '__main__':
    print(get_response('hello'))
