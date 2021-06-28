<?php 

class epgu_lib{
	
	// прод 10.3.60.3:8031 (нужен проброс через випнет)
	// тест 85.142.162.12:8031
	private $server = 'http://10.3.60.3:8031';
	
	// данные организации (используются перманентно в запросах к апи)
	private $org = array(
		'ogrn'	=> '1111111111111',
		'kpp'	=> '222222222'
	);
	
	// директория для манипуляций с подписыванием ЭЦП
	private $crypto_dir = '/files/epgu/';
	
	// префикс шелл-вызова утилиты cryptcp
	// важно вызывать под sudo юзером
	// об утилите https://www.cryptopro.ru/products/other/cryptcp
	private $cryptcp_prefix = 'sudo -u superuser /path/to/cryptcp/';
	
	// отпечаток сертификата ЭЦП
	private $thumbprint = 'fc5ae1adab2ea6d909fb13b16238993464bc2134';
			
	// начальное значение таймаута в секундах перед отправкой запроса к очереди
	// далее по принципу, описанному в max_iterations
	private $q_timeout = 3;
	
	// количество попыток извлечь данные из очереди
	// после первого запроса устанавливается таймаут = № попытки * 3 секунд
	private $max_iterations = 5;
	
		
	function __construct(){
		$this->crypto_dir = $_SERVER['DOCUMENT_ROOT'].'/'.trim($this->crypto_dir, '/');		
	}
		
	public function queue($q = array()){
		
		$q = is_array($q) ? $q : [];
		
		$result = array('success' => false);
		
		if($this->checkPerms()){
		
			$q_sended = $this->setQueue($q);
			$q_sended = $q_sended ? $q_sended : ['error' => 'Пустой ответ от сервиса при отправке в очередь'];
			
			$result['success'] = isset($q_sended['idJwt']);
			
			if($result['success']){
				
				$q_result = $this->getQueue($q_sended['idJwt']);
				$q_result = $q_result ? $q_result : ['error' => 'Пустой ответ от сервиса при получении очереди'];
				
				$result['success'] = isset($q_result['payload']);
				
				if($result['success']){
					$result['payload'] = $q_result['payload'];
				}else{
					$result['error'] = isset($q_result['error']) ? $q_result['error'] : 'Неизвестная ошибка при получении очереди';
				}
							
			}else{
				$result['error'] = isset($q_sended['error']) ? $q_sended['error'] : 'Неизвестная ошибка при отправке в очередь';
			}
			
		}else{
			$result['error'] = 'Нет прав для выполнения запроса';
		}
		
		return $result;
	}
	
	public function cls($q = array()){
		
		$q = is_array($q) ? $q : [];
		
		$result = array('success' => false);
		
		$q['cls'] = isset($q['cls']) ? $q['cls'] : 'Directions';
		
		$q_result = $this->send('/api/cls/request', array_merge($this->org, $q));
		$q_result = $q_result ? $q_result : ['error' => 'Пустой ответ от сервиса при получении справочников'];
		
		$result['success'] = !isset($q_result['error']);
		
		if($result['success']) $result['payload'] = $q_result;
		
		return $result;
	}
	
	public function checkCrypto(){
		return $this->send('/api/certificate/check', ['header' => $this->org, 'payload' => '']);
	}
	
	private function send($uri = '', $data = array()){
		
		$data = is_array($data) ? $data : [];
		
		$cls_request = false;
		
		if(preg_match('/(cls)/i', $uri)){
			
			$body = $data;
			
			$cls_request = true;
			
		}else{
			
			if(!isset($data['header']) || !isset($data['payload'])){
				return ['error' => 'Не указан header или payload'];
			}
			
			$data['header'] = json_encode($data['header']);
			
			$jwt = base64_encode($data['header']).'.'.base64_encode($data['payload']);
			
			$signed_request = $this->sign($jwt);
			
			if(isset($signed_request['signature'])){
				$jwt .= '.'.$signed_request['signature'];
			}else{
				return $signed_request;
			}
						
			$body = ['token' => $jwt];
		}
		
		$ch = curl_init($this->server.'/'.trim($uri, '/'));
		
		curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_NOSIGNAL, 1); // для корректной обработки таймаута
		curl_setopt($ch, CURLOPT_TIMEOUT, 5); // ожидание выполнения в секундах
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3); // ожидание соединения в секундах
		
		$output = curl_exec($ch);
		
		curl_close($ch);
		
		$output = $cls_request ? $output : json_decode($output, true);
		
		return $output;
	}
	
	private function sign($data = ''){
		
		if(!is_dir($this->crypto_dir)) return ['error' => 'Некорректно указана директория для работы с ЭЦП'];
		
		// файл для входящей строки и дальнейшей подписи
		$file_msg = sprintf($this->crypto_dir.'/msg-%d.txt', getmypid());
		
		file_put_contents($file_msg, $data);
		
		// файл на выход в формате $file_msg.sgn
		// Создаётся автоматически при подписи
		$file_sign = $file_msg.'.sgn';
				
		// для подписи файла
		$signing = shell_exec($this->cryptcp_prefix."cryptcp -sign -der -strict -cert -detached -thumbprint ".$this->thumbprint." ".$file_msg."");
						
		// вычленяем статус подписи
		preg_match_all('/(\[ErrorCode: (.*)\])/i', $signing, $signing_res);
		
		// удаляем файл с входящей строкой
		if(file_exists($file_msg)) unlink($file_msg);
		
		if($signing_res[2][0] != '0x00000000'){
			return ['error' => 'Не удалось подписать файл. Ошибка '.$signing_res[2][0]];
		}
				
		// извлекаем сигнатуру из подписанного файла
		$signature = base64_encode(file_get_contents($file_sign));
		
		// удаляем подписанный файл
		if(file_exists($file_sign)) unlink($file_sign);
						
		return ['signature' => $signature];
	}
		
	private function setQueue($data = array()){
	
		$data = is_array($data) ? $data : [];
	
		$data['header'] = is_array($data['header']) ? array_merge($this->org, $data['header']) : $this->org;
		$data['payload'] = isset($data['payload']) ? $data['payload'] : '';
				
		return $this->send('/api/token/new', $data);
	}
	
	private function getQueue($id_jwt = 0){
	
		$id_jwt = intval($id_jwt);
		
		$this->q_timeout = intval($this->q_timeout);
		
		$this->max_iterations = intval($this->max_iterations);
		
		$result = $data = array();
		
		if($id_jwt == 0){
			$result['error'] = 'Некорректный номер очереди';
		}else{
		
			$data['header'] = array_merge($this->org, ['idJwt' => $id_jwt, 'action' => 'getMessage']);
			$data['payload'] = '';
			
			$iteration = 1;
			
			while(empty($result)){
							
				if($iteration <= $this->max_iterations){
									
					sleep($this->q_timeout);
				
					$result = $this->extractResponse($this->send('/api/token/service/info', $data));
					
					$this->q_timeout = $iteration * 3;
					
					$iteration++;	
					
				}else{
					$result['error'] = 'Не удаётся получить данные из очереди (попыток: '.$this->max_iterations.', крайний таймаут перед запросом: '.$this->q_timeout.' секунд)';
				}
						
			}
			
			$this->confirmQueue($id_jwt);
			
		}
		
		return $result;
	}
	
	private function confirmQueue($id_jwt = 0){
		
		$id_jwt = intval($id_jwt);
		
		$data = array();
		
		if($id_jwt == 0) return false;
				
		$data['header'] = array_merge($this->org, ['idJwt' => $id_jwt, 'action' => 'messageConfirm']);
		$data['payload'] = '';
		
		return $this->send('/api/token/confirm', $data);
	}
	
	private function extractResponse($data = array()){
		
		$result = array();
		
		// если данных в очереди нет (смотрим по паттерну в ошибке)
		// то возвращаем пустой массив, что позволит продолжить работу в цикле
		if(isset($data['error']) && preg_match('/(отсутствуют)/ui', $data['error'])) return $result;
		
		if(isset($data['responseToken'])){
			
			$resp_data = explode('.', $data['responseToken']);
			
			$result['header'] = base64_decode($resp_data[0]);
			$result['payload'] = base64_decode($resp_data[1]);
			
		}else{
			$result = $data;
		}
		
		return $result;
	}
	
	// если нужно проверить права на метод очередей
	private function checkPerms(){
		return true;
	}

}

?>
