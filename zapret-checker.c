/*************************************************************************
* Zapret-checker daemon is a set of program and system configurations    *
*                                       to block blacklisted websites.   *
* Blacklist is retrieved from http://vigruzki.rkn.gov.ru/                *
* Written by Matrizaev Vyacheslav.                                       *
*************************************************************************/

#include "zapret-checker.h"

/*************************************************************************
* Демон может находиться в одном из состояний:                           *
* 1. Запуск и инициализации     -> Переконфигурация                      *
* 2. Переконфигурация           -> Активное состояние                    *
* 3. Активное состояние         -> Переконфигурация | Выключение         *
* 4. Выключение                                                          *
*************************************************************************/

/*************************************************************************
* Запуск и инициализация:                                                *
* 1. Установка обработчика сигналов.                                     *
* 2. Инициализация библиотек libXML2, libCURL, OpenSSL, NFQUEUE.         *
*************************************************************************/

/*************************************************************************
* Переконфигурация:                                                      *
* 1. Остановка потоков обработки трафика и очистка всех контекстов.      *
* 2. Валидация и разбор конфигурационного файла.                         *
* 3. Выделение памяти и инициализация контекстов.                        *
* 4. Если необходимо, разбор пользовательского реестра запрещённых сайтов*
* 5. Обновление списков доступа IPSET.                                   *
* 6. Запуск потоков обработки трафика.                                   *
*************************************************************************/

/*************************************************************************
* Активное состояние:                                                    *
* 1. Если необходимо, взаимодействие с SOAP сервером.                    *
*    а) Разбор выгрузки реестра запрещённых сайтов РосКомНадзора.        *
*    б) Рассылка EMAIL сообщений с экземпляром выгрузки и отчетом        *
*                                                      о состоянии.      *
*    в) Перезапуск потоков обработки трафика.                            *
*    г) Обновление списков доступа IPSET.                                *
* 2. Переход главного потока в спящее состояние.                         *
*************************************************************************/

/*************************************************************************
* Выключение:                                                            *
* 1. Остановка потоков обработки трафика и очистка всех контекстов.      *
* 2. Деинициализация библиотек libXML2, libCURL, OpenSSL, NFQUEUE.       *
*************************************************************************/

/*************************************************************************
* Глобальные флаги состояния демона:                                     *
* flagMatrixShutdown - флаг сигнализирущий о необходимости останова      *
* flagMatrixReconfigure - флаг сигнализирущий о необходимости перечитать *
*                                               файл конфигурации.       *
* flagMatrixReload - флаг сигнализирущий о необходимости остановить      *
*                                          потоки обработки трафика      *
* Флаги обрабатываются один раз за итерацию главного цикла.              *
*************************************************************************/

volatile sig_atomic_t	flagMatrixShutdown = 0;
volatile sig_atomic_t	flagMatrixReconfigure = 1;
volatile sig_atomic_t	flagMatrixReload = 0;

/*************************************************************************
* Обработчики сигналов SIGHUP, SIGTERM и SIGINT.                         *
*************************************************************************/

static void TerminateSignalHandler ()
{
	flagMatrixShutdown = 1;
}

static void HupSignalHandler ()
{
	flagMatrixReconfigure = 1;
}

static void IntSignalHandler ()
{
	flagMatrixReload = 1;
}

/*************************************************************************
* Инициализация обработчиков сигналов.                                   *
*************************************************************************/

static bool ConfigureSignalHandlers ()
{
	struct sigaction sigSA;

	/*************************************************************************
	* Инициализация обработчика SIGTERM для "мягкого" завершения демона.     *
	*************************************************************************/
	memset (&sigSA, 0, sizeof (struct sigaction));
	sigSA.sa_handler = TerminateSignalHandler;
	check (sigemptyset (&sigSA.sa_mask) != -1, ERROR_STR_SIGNALHANDLER);
	sigSA.sa_flags = 0;
	check (sigaction (SIGTERM, &sigSA, NULL) != -1, ERROR_STR_SIGNALHANDLER);

	/*************************************************************************
	* Инициализация обработчика SIGHUP для перечитывания конфигурации.       *
	*************************************************************************/
	memset (&sigSA, 0, sizeof (struct sigaction));
	sigSA.sa_handler = HupSignalHandler;
	check (sigemptyset (&sigSA.sa_mask) != -1, ERROR_STR_SIGNALHANDLER);
	sigSA.sa_flags = 0;
	check (sigaction (SIGHUP, &sigSA, NULL) != -1, ERROR_STR_SIGNALHANDLER);

	/*************************************************************************
	* Инициализация обработчика SIGINT для перезапуска потоков фильтрации.   *
	*************************************************************************/
	memset (&sigSA, 0, sizeof (struct sigaction));
	sigSA.sa_handler = IntSignalHandler;
	check (sigemptyset (&sigSA.sa_mask) != -1, ERROR_STR_SIGNALHANDLER);
	sigSA.sa_flags = 0;
	check (sigaction (SIGINT, &sigSA, NULL) != -1, ERROR_STR_SIGNALHANDLER);
	return true;
error:
	return false;
}

/*************************************************************************
* Функция обновления списка IP адресов IPSET.                            *
*************************************************************************/
static void UpdateIpsetList(char* ipsetList, pfHashTable *hashTable)
{
	if (hashTable == NULL || ipsetList == NULL)
		return;
	
	
	/*************************************************************************
	* Массив дескрипторов канала. [0] для чтения, [1] для записи.            *
	*************************************************************************/	
	int fd[2] = {-1};
	FILE *fout = NULL;
	pid_t child = -1;
	
	
	/*************************************************************************
	* Создаём канал связи с дочерним процессом.                              *
	*************************************************************************/
	check (pipe (fd) != -1, ERROR_STR_IPSET1);
	
	/*************************************************************************
	* Дублируем процесс.                                                     *
	*************************************************************************/
	child = fork();
	check (child != -1, ERROR_STR_IPSET1);
	if (child == 0)
	{
		
		/*************************************************************************
		* Дочерний процесс.                                                      *
		*************************************************************************/
		
		/*************************************************************************
		* Дублируем STDIN дочернего процесса для последующего чтения из него.      *
		*************************************************************************/
		if (dup2(fd[0], 0) == -1)
			exit(EXIT_FAILURE);
		
		/*************************************************************************
		* Закрываем дескрипторы канала.                                          *
		*************************************************************************/
		close (fd[1]);
		close (fd[0]);
		
		/*************************************************************************
		* Заменяем дочерний процесс на ipset.                                    *
		*************************************************************************/
		if (execlp ("ipset", "ipset", "restore", (char *)NULL) == -1)
			exit(EXIT_FAILURE);
	}
	
	/*************************************************************************
	* Родительский процесс.                                                  *
	*************************************************************************/
	
	/*************************************************************************
	* Открываем поток для записи в канал.                                    *
	*************************************************************************/
	
	fout = fdopen( fd[1], "w" );
	check (fout != NULL, ERROR_STR_IPSET1);

	/*************************************************************************
	* Создаём временный список ipset.                                        *
	*************************************************************************/

	check (fprintf (fout, "-exist create ZAPRET_TEMP hash:net maxelem 100000000\n") > 0, ERROR_STR_IPSET1);

	/*************************************************************************
	* Добавляем в временный список актуальный IP адреса.                     *
	*************************************************************************/
	for (size_t i = 0; i < hashTable->numEntries; i++)
	{
		for (pfHashNode *node = hashTable->lookup[i]; node != NULL; node = node->next)
		{
			check (fprintf (fout, "-exist add ZAPRET_TEMP %s\n", node->key) > 0, ERROR_STR_IPSET1);
		}
	}
	
	/*************************************************************************
	* Обмениваем временный список ipset с рабочим и уничтожаем временный.    *
	*************************************************************************/
	check (fprintf (fout, "swap ZAPRET_TEMP %s\n", ipsetList) > 0, ERROR_STR_IPSET1);
	check (fprintf (fout, "destroy ZAPRET_TEMP\n") > 0, ERROR_STR_IPSET1);
	
	/*************************************************************************
	* Ждём завершения дочернего процесса.    *
	*************************************************************************/
error:
	if (fout != NULL)
		if (fflush (fout) != 0)
		{
			log_err (ERROR_STR_IPSET1);
		}
	if (fd[0] != -1)
		close (fd[0]);
	if (fd[1] != -1)
		close (fd[1]);
	if (child > 0)
	{
		int wstatus = 0;
		if (waitpid(child, &wstatus, 0) == -1)
		{
			log_err (ERROR_STR_IPSET1);
		}
	}
	return;
}

/*************************************************************************
* Главная функция демона.                                                *
*************************************************************************/
int main ()
{
	int exitCode = EXIT_FAILURE;
	TZapretContext context;
	
	/*************************************************************************
	* Начальная инициализация используемых библиотек.                        *
	*************************************************************************/
	memset (&context, 0, sizeof (context));
	check (ConfigureSignalHandlers () == true, ERROR_STR_INITIALIZATION);
	LIBXML_TEST_VERSION
	xmlInitParser ();
	check (curl_global_init (CURL_GLOBAL_ALL) == 0, ERROR_STR_INITIALIZATION);
	
	/*************************************************************************
	* Главный цикл демона.                                                   *
	*************************************************************************/
	while (flagMatrixShutdown == 0)
	{
		time_t sleepTime = 0;
		bool soapResult = false;
		
		/*************************************************************************
		* Выполняем чтение конфигурационного файла.                              *
		*************************************************************************/
		if (flagMatrixReconfigure == 1)
		{
			log_info ("Reconfiguring.");

			/*************************************************************************
			* Очищаем все контексты, останавливаем потоки, обрабатываем файл         *
			* конфигурации.                                                          *
			*************************************************************************/
			ClearZapretContext (&context);
			check (ReadZapretConfiguration (&context) == true, ERROR_STR_CONFIGURATION);
			flagMatrixReconfigure = 0;

			/*************************************************************************
			* Создаём хеш-таблицы.                                                   *
			*************************************************************************/
			for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++)
			{
				context.hashTables[i] = pfHashCreate (NULL, 15013);
				check_mem (context.hashTables[i]);
			}

			/*************************************************************************
			* Обрабатываем пользовательский файл запрещённых ресурсов.               *
			*************************************************************************/
			if (context.customBlacklist != NULL)
			{
				log_info ("Parsing custom blacklist.");
				if (ProcessRegisterCustomBlacklist(context.redirectNSLookup, context.customBlacklist, context.hashTables) != true)
				{
					log_err(ERROR_STR_CUSTOMBL);
				}
			}
			if (context.dnsThreadsContext != NULL || context.httpThreadsContext != NULL)
			{
				/*************************************************************************
				* Запускаем потоки фильтрации.                                           *
				*************************************************************************/			
				log_info ("Starting filtering threads.");
				StartNetfilterProcessing (context.httpThreadsContext, context.redirectHTTPCount, context.hashTables[NETFILTER_TYPE_HTTP]);
				StartNetfilterProcessing (context.dnsThreadsContext,  context.redirectDNSCount,  context.hashTables[NETFILTER_TYPE_DNS]);
			}

			/*************************************************************************
			* Обновляем списки IPSET.                                                *
			*************************************************************************/	
			if (context.redirectIpsetList != NULL)
			{
				log_info ("Updating ipset list.");
				UpdateIpsetList(context.redirectIpsetList, context.hashTables[NETFILTER_TYPE_IP]);
			}
		}

		/*************************************************************************
		* Если возможно, обращаемся к серверу РосКомНадзора.                     *
		*************************************************************************/	
		if (context.blacklistHost != NULL && context.requestXmlDoc != NULL)
		{

			/*************************************************************************
			* Засекаем начало взаимодействия.                                        *
			*************************************************************************/
			time_t workingPeriod = time(NULL);

			/*************************************************************************
			* Обращаемся к серверу РосКомНадзора.                                    *
			*************************************************************************/
			log_info ("Communicating with SOAP server.");
			PerformSOAPCommunication (&context);

			/*************************************************************************
			* В случае успеха посылаем уведомление администратору по email и         *
			* обрабатываем выгрузку.                                                 *
			*************************************************************************/			
			if (context.soapContext != NULL)
			{
				log_info ("Sending emails.");
				SendSMTPMessage (context.smtpContext, context.soapContext);
				soapResult = context.soapContext->soapResult;
				if (context.soapContext->registerZipArchive != NULL)
				{

					/*************************************************************************
					* Обрабатываем выгрузку файла запрещённых ресурсов РосКомНадзора.        *
					*************************************************************************/
					log_info ("Parsing RKN blacklist.");
					pfHashTable **hashTables = ProcessRegisterZipArchive (context.soapContext->registerZipArchive, context.redirectNSLookup, context.timestampFile);
					if (hashTables != NULL)
					{

						/*************************************************************************
						* Обрабатываем пользовательский файл запрещённых ресурсов.               *
						*************************************************************************/
						if (context.customBlacklist != NULL)
						{
							log_info ("Parsing custom blacklist.");
							if (ProcessRegisterCustomBlacklist(context.redirectNSLookup, context.customBlacklist, hashTables) != true)
							{
								log_err(ERROR_STR_CUSTOMBL);
							}
						}
				
						if (context.dnsThreadsContext != NULL || context.httpThreadsContext != NULL)
						{
							/*************************************************************************
							* Останавливаем потоки фильтрации.                                       *
							*************************************************************************/		
							log_info ("Stoping filtering threads.");
							StopNetfilterProcessing (context.httpThreadsContext, context.redirectHTTPCount);
							StopNetfilterProcessing (context.dnsThreadsContext, context.redirectDNSCount);
						}

						/*************************************************************************
						* Актуализируем хеш-таблицы.                                             *
						*************************************************************************/	
						for (size_t i = 0; i < NETFILTER_TYPE_COUNT; i++)
						{
							if (context.hashTables[i] != NULL)
								pfHashDestroy(context.hashTables[i]);
							context.hashTables[i] = hashTables[i];
						}
						free (hashTables);
						
						if (context.dnsThreadsContext != NULL || context.httpThreadsContext != NULL)
						{
							/*************************************************************************
							* Запускаем потоки фильтрации.                                           *
							*************************************************************************/			
							log_info ("Starting filtering threads.");
							StartNetfilterProcessing (context.httpThreadsContext, context.redirectHTTPCount, context.hashTables[NETFILTER_TYPE_HTTP]);
							StartNetfilterProcessing (context.dnsThreadsContext,  context.redirectDNSCount,  context.hashTables[NETFILTER_TYPE_DNS]);
						}

						/*************************************************************************
						* Обновляем списки IPSET.                                                *
						*************************************************************************/	
						if (context.redirectIpsetList != NULL)
						{
							log_info ("Updating ipset list.");
							UpdateIpsetList (context.redirectIpsetList, context.hashTables[NETFILTER_TYPE_IP]);
						}
					}
					else
					{
						log_err(ERROR_STR_IPSET1);
					}
				}
			}

			/*************************************************************************
			* Очищаем контекст SOAP для следующих итераций.                          *
			*************************************************************************/	
			ClearSOAPContext (context.soapContext);

			/*************************************************************************
			* Вычисляем задержку перед следующей итерацией.                          *
			*************************************************************************/	
			workingPeriod = time(NULL) - workingPeriod;
			if (workingPeriod < context.blacklistCooldownPositive && soapResult == true)
				sleepTime = context.blacklistCooldownPositive - workingPeriod;
			else
				sleepTime = context.blacklistCooldownNegative;
			if (sleepTime <= 0)
				sleepTime = 1;
		}
		
		/*************************************************************************
		* Засыпаем перед следующей итерацией.                                    *
		*************************************************************************/	
		if (flagMatrixShutdown == 1)
			break;
		if (flagMatrixReconfigure == 1)
			continue;
		log_info ("Going to sleep.");
		if (sleepTime == 0)
			pause ();
		else
			sleep (sleepTime);
	}

	log_info ("Soft shutdown.");
	exitCode = EXIT_SUCCESS;
error:

	/*************************************************************************
	* Перед выходом очищаем использованные ресурсы.                          *
	*************************************************************************/	
	ClearZapretContext (&context);
	xmlCleanupParser ();
	Base64Cleanup ();
	curl_global_cleanup ();
	return exitCode;
}