#!/usr/bin/env python3
import os, sys, re, json, logging as log, threading, urllib3, requests, random
from time import time, sleep
DEBUG = 0#+1
CONFIG = sys.argv[1] if len(sys.argv)>1 else 'students.json' # take cli arg or default
CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), CONFIG) # relative to file
# CONFIG = '/etc/jlu.conf' # force a config file here
RETRIES = 100
TIMEOUT = 2
INTERVAL = 0.5
m = MessageSender.MessageSender("bark")
m.config({"apikey": ""})

def runTask(task):
	for tries in range(RETRIES):
		try:
			s = requests.Session()
			s.headers.update({'Referer': 'https://ehall.jlu.edu.cn/'})
			s.verify = False
			
			log.info('Authenticating...')
			r = s.get('https://ehall.jlu.edu.cn/jlu_portal/login', timeout=TIMEOUT)
			pid = re.search('(?<=name="pid" value=")[a-z0-9]{8}', r.text)[0]
			log.debug(f"PID: {pid}")
			postPayload = {'username': task['username'], 'password': task['password'], 'pid': pid}
			r = s.post('https://ehall.jlu.edu.cn/sso/login', data=postPayload, timeout=TIMEOUT)

			log.info('Requesting form...')
			r = s.get(f"https://ehall.jlu.edu.cn/infoplus/form/{task['transaction']}/start", timeout=TIMEOUT)
			csrfToken = re.search('(?<=csrfToken" content=").{32}', r.text)[0]
			log.debug(f"CSRF: {csrfToken}")
			postPayload = {'idc': task['transaction'], 'csrfToken': csrfToken}
			r = s.post('https://ehall.jlu.edu.cn/infoplus/interface/start', data=postPayload, timeout=TIMEOUT)
			sid = re.search('(?<=form/)\\d*(?=/render)', r.text)[0]
			log.debug(f"Step ID: {sid}")
			postPayload = {'stepId': sid, 'csrfToken': csrfToken}
			r = s.post('https://ehall.jlu.edu.cn/infoplus/interface/render', data=postPayload, timeout=TIMEOUT)
			data = json.loads(r.content)['entities'][0]

			log.info('Submitting form...')
			for k, v in task['fields'].items():
				if eval(task['conditions'].get(k, 'True')):
					data['data'][k] = v
			postPayload = {
				'actionId': 1,
				'formData': json.dumps(data['data']),
				'nextUsers': '{}',
				'stepId': sid,
				'timestamp': int(time()),
				'boundFields': ','.join(data['fields'].keys()),
				'csrfToken': csrfToken
			}
			log.debug(f"Payload: {postPayload}")
			r = s.post('https://ehall.jlu.edu.cn/infoplus/interface/doAction', data=postPayload, timeout=TIMEOUT)
			log.debug(f"Result: {r.text}")
			if json.loads(r.content)['ecode'] != 'SUCCEED' :
				raise Exception('The server returned a non-successful status.')
			log.info('Success!')
			if tries == 0:
			  content = "一次就填报成功了呢~"
			else:
			  content = "尝试了大概%s次，不过还是成功了呢~" % str(tries + 1)
			msg = {"title": "为%s填报成功！" % task['username'], "content": content}
			m.send(msg)
			return
		except Exception as e:
			log.error(e)
      		msg = {"title": "啊这，为%s填报失败！" % task['username'], "content": "重试次数过多！" + e.__str__()}
			sleep(random.randint(1, TIMEOUT))
	log.error('Failed too many times, exiting...')
 	m.send(msg)

log.basicConfig(
	level=log.INFO-10*DEBUG,
	format='%(asctime)s %(threadName)s:%(levelname)s %(message)s'
)
log.warning('Started.')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log.info(f'Reading config from {CONFIG}')
config = json.load(open(CONFIG))
for task in config.get('tasks', [{}]):
	for k in ['username', 'password', 'transaction']:
		task.setdefault(k, config.get(k))
	for k in ['fields', 'conditions']:
		task[k] = {**config.get(k, {}), **task.get(k, {})}
	if task['transaction']:
		threading.Thread(
			target=runTask,
			name=f"{task['transaction']}:{task['username']}",
			args=(task,)
		).start()
	sleep(INTERVAL)
