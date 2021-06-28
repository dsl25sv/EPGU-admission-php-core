# EPGU-admission-php-core
Класс для обмена данными с сервисом приёма (ЕПГУ)

<h2>Проверка привязки сертификата и криптопровайдера</h2>

```
$epgu = new epgu_lib;
$result = $epgu->checkCrypto();
```

<h2>Справочники</h2>

```
$epgu = new epgu_lib;
$result = $epgu->cls(['cls' => 'Directions']);
```

<h2>Очереди</h2>

Работа с очередями сделана через луп и таймауты на запросы извлечения.
Всё происходит одним потоком (постановка, затем сразу пробуем извлекать).

```
$epgu = new epgu_lib;

$q = [];
$q['header'] = ['action' => 'get', 'entityType' => 'campaign'];
$q['payload'] = '
	<PackageData>
		<Campaign>
			<UID>2021</UID>
		</Campaign>
	</PackageData>
';
		
$result = $epgu->queue($q);
```

Результат имеет структуру:

```
array(1) {
	["success"]=> bool Успех или провал
	["error"]=> string Причина провала
	["payload"]=> string Полезная нагрузка
}
```
