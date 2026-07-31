/*************************************************************************
 * Zapret-checker daemon is a set of program and system configurations    *
 *                                       to block blacklisted websites.   *
 * Blacklist is retrieved from http://vigruzki.rkn.gov.ru/                *
 * Written by Matrizaev Vyacheslav.                                       *
 *************************************************************************/

#include "allheaders.h"

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

volatile sig_atomic_t flagMatrixShutdown = 0;
volatile sig_atomic_t flagMatrixReconfigure = 1;
volatile sig_atomic_t flagMatrixReload = 0;

/*************************************************************************
 * Обработчики сигналов SIGHUP, SIGTERM и SIGINT.                         *
 *************************************************************************/

static void TerminateSignalHandler(int signalNumber) {
  (void)signalNumber;
  flagMatrixShutdown = 1;
}

static void HupSignalHandler(int signalNumber) {
  (void)signalNumber;
  flagMatrixReconfigure = 1;
}

static void IntSignalHandler(int signalNumber) {
  (void)signalNumber;
  flagMatrixReload = 1;
}

/*************************************************************************
 * Инициализация обработчиков сигналов.                                   *
 *************************************************************************/

static bool ConfigureSignalHandlers() {
  struct sigaction sigSA;

  /*************************************************************************
   * Инициализация обработчика SIGTERM для "мягкого" завершения демона.     *
   *************************************************************************/
  memset(&sigSA, 0, sizeof(struct sigaction));
  sigSA.sa_handler = TerminateSignalHandler;
  check(sigemptyset(&sigSA.sa_mask) != -1, ERROR_STR_SIGNALHANDLER);
  sigSA.sa_flags = 0;
  check(sigaction(SIGTERM, &sigSA, NULL) != -1, ERROR_STR_SIGNALHANDLER);

  /*************************************************************************
   * Инициализация обработчика SIGHUP для перечитывания конфигурации.       *
   *************************************************************************/
  memset(&sigSA, 0, sizeof(struct sigaction));
  sigSA.sa_handler = HupSignalHandler;
  check(sigemptyset(&sigSA.sa_mask) != -1, ERROR_STR_SIGNALHANDLER);
  sigSA.sa_flags = 0;
  check(sigaction(SIGHUP, &sigSA, NULL) != -1, ERROR_STR_SIGNALHANDLER);

  /*************************************************************************
   * Инициализация обработчика SIGINT для перезапуска потоков фильтрации.   *
   *************************************************************************/
  memset(&sigSA, 0, sizeof(struct sigaction));
  sigSA.sa_handler = IntSignalHandler;
  check(sigemptyset(&sigSA.sa_mask) != -1, ERROR_STR_SIGNALHANDLER);
  sigSA.sa_flags = 0;
  check(sigaction(SIGINT, &sigSA, NULL) != -1, ERROR_STR_SIGNALHANDLER);
  return true;
error:
  return false;
}

/*************************************************************************
 * Функция обновления списка IP адресов IPSET.                            *
 *************************************************************************/
static void UpdateIpsetList(char *ipsetList, const pfHashSet *ipAddresses) {
  if (ipAddresses == NULL || ipsetList == NULL)
    return;

  /*************************************************************************
   * Массив дескрипторов канала. [0] для чтения, [1] для записи.            *
   *************************************************************************/
  int fd[2] = {-1, -1};
  FILE *fout = NULL;
  pid_t child = -1;

  /*************************************************************************
   * Создаём канал связи с дочерним процессом.                              *
   *************************************************************************/
  check(pipe(fd) != -1, ERROR_STR_IPSET1);

  /*************************************************************************
   * Дублируем процесс.                                                     *
   *************************************************************************/
  child = fork();
  check(child != -1, ERROR_STR_IPSET1);
  if (child == 0) {

    /*************************************************************************
     * Дочерний процесс.                                                      *
     *************************************************************************/

    /*************************************************************************
     * Дублируем STDIN дочернего процесса для последующего чтения из него. *
     *************************************************************************/
    if (dup2(fd[0], 0) == -1)
      exit(EXIT_FAILURE);

    /*************************************************************************
     * Закрываем дескрипторы канала.                                          *
     *************************************************************************/
    close(fd[1]);
    close(fd[0]);

    /*************************************************************************
     * Заменяем дочерний процесс на ipset.                                    *
     *************************************************************************/
    if (execlp("ipset", "ipset", "restore", (char *)NULL) == -1)
      exit(EXIT_FAILURE);
  }

  /*************************************************************************
   * Родительский процесс.                                                  *
   *************************************************************************/

  /*************************************************************************
   * Открываем поток для записи в канал.                                    *
   *************************************************************************/

  fout = fdopen(fd[1], "w");
  check(fout != NULL, ERROR_STR_IPSET1);
  fd[1] = -1;

  /*************************************************************************
   * Создаём временный список ipset.                                        *
   *************************************************************************/

  check(fprintf(fout,
                "-exist create ZAPRET_TEMP hash:net maxelem 100000000\n") > 0,
        ERROR_STR_IPSET1);

  /*************************************************************************
   * Добавляем в временный список актуальный IP адреса.                     *
   *************************************************************************/
  for (uint32_t i = 0; i < ipAddresses->bucketCount; i++) {
    for (const pfHashSetNode *node = ipAddresses->lookup[i]; node != NULL;
         node = node->next) {
      check(fprintf(fout, "-exist add ZAPRET_TEMP %s\n", node->key) > 0,
            ERROR_STR_IPSET1);
    }
  }

  /*************************************************************************
   * Обмениваем временный список ipset с рабочим и уничтожаем временный.    *
   *************************************************************************/
  check(fprintf(fout, "swap ZAPRET_TEMP %s\n", ipsetList) > 0,
        ERROR_STR_IPSET1);
  check(fprintf(fout, "destroy ZAPRET_TEMP\n") > 0, ERROR_STR_IPSET1);

  /*************************************************************************
   * Ждём завершения дочернего процесса.    *
   *************************************************************************/
error:
  if (fout != NULL) {
    if (fclose(fout) != 0)
      log_err(ERROR_STR_IPSET1);
    fout = NULL;
  }
  if (fd[0] != -1)
    close(fd[0]);
  if (fd[1] != -1)
    close(fd[1]);
  if (child > 0) {
    int wstatus = 0;
    if (waitpid(child, &wstatus, 0) == -1) {
      log_err(ERROR_STR_IPSET1);
    }
  }
  return;
}

/*************************************************************************
 * Главная функция демона.                                                *
 *************************************************************************/
int main(int argc, char *argv[]) {
  int exitCode = EXIT_FAILURE;
  const char *configurationFile = ZAPRET_DEFAULT_CONFIG_FILE;
  const uint32_t blacklistBucketCounts[NETFILTER_TYPE_COUNT] = {
      ZAPRET_HTTP_HASH_BUCKET_COUNT, ZAPRET_DNS_HASH_BUCKET_COUNT,
      ZAPRET_IP_HASH_BUCKET_COUNT};
  TZapretContext context;

  if (argc == 3 &&
      (!strcmp(argv[1], "-c") || !strcmp(argv[1], "--config"))) {
    configurationFile = argv[2];
  } else if (argc != 1) {
    fprintf(stderr, "Usage: %s [-c|--config FILE]\n", argv[0]);
    return EXIT_FAILURE;
  }

  /*************************************************************************
   * Начальная инициализация используемых библиотек.                        *
   *************************************************************************/
  memset(&context, 0, sizeof(context));
  check(ConfigureSignalHandlers() == true, ERROR_STR_INITIALIZATION);
  LIBXML_TEST_VERSION
  xmlInitParser();
  check(curl_global_init(CURL_GLOBAL_ALL) == 0, ERROR_STR_INITIALIZATION);

  /*************************************************************************
   * Главный цикл демона.                                                   *
   *************************************************************************/
  while (flagMatrixShutdown == 0) {
    time_t sleepTime = 0;
    bool soapResult = false;

    /*************************************************************************
     * Выполняем чтение конфигурационного файла.                              *
     *************************************************************************/
    if (flagMatrixReconfigure == 1) {
      log_info("Reconfiguring.");

      /*************************************************************************
       * Очищаем все контексты, останавливаем потоки, обрабатываем файл *
       * конфигурации. *
       *************************************************************************/
      ClearZapretContext(&context);
      check(ReadZapretConfiguration(&context, configurationFile) == true,
            ERROR_STR_CONFIGURATION);
      flagMatrixReconfigure = 0;

      /*************************************************************************
       * Создаём хеш-таблицы. *
       *************************************************************************/
      check(InitializeZapretBlacklist(&context.blacklist,
                                      blacklistBucketCounts),
            ERROR_STR_INITIALIZATION);

      /*************************************************************************
       * Обрабатываем пользовательский файл запрещённых ресурсов. *
       *************************************************************************/
      if (context.customBlacklist != NULL) {
        log_info("Parsing custom blacklist.");
        if (ProcessRegisterCustomBlacklist(context.redirectNSLookup,
                                           context.customBlacklist,
                                           &context.blacklist) != true) {
          log_err(ERROR_STR_CUSTOMBL);
        }
      }
      if (context.dnsThreadsContext != NULL ||
          context.httpThreadsContext != NULL) {
        /*************************************************************************
         * Запускаем потоки фильтрации. *
         *************************************************************************/
        log_info("Starting filtering threads.");
        StartHTTPNetfilterProcessing(context.httpThreadsContext,
                                     context.redirectHTTPCount,
                                     context.blacklist.httpRules);
        StartDNSNetfilterProcessing(context.dnsThreadsContext,
                                    context.redirectDNSCount,
                                    context.blacklist.dnsNames);
      }

      /*************************************************************************
       * Обновляем списки IPSET. *
       *************************************************************************/
      if (context.redirectIpsetList != NULL) {
        log_info("Updating ipset list.");
        UpdateIpsetList(context.redirectIpsetList,
                        context.blacklist.ipAddresses);
      }
    }

    /*************************************************************************
     * Если возможно, обращаемся к серверу РосКомНадзора.                     *
     *************************************************************************/
    if (context.blacklistHost == NULL) {
      log_info("context.blacklistHost == NULL");
    }
    if (context.requestXmlDoc == NULL) {
      log_info("context.context.requestXmlDoc == NULL");
    }
    if (context.blacklistHost != NULL && context.requestXmlDoc != NULL) {

      /*************************************************************************
       * Засекаем начало взаимодействия. *
       *************************************************************************/
      time_t workingPeriod = time(NULL);

      /*************************************************************************
       * Обращаемся к серверу РосКомНадзора. *
       *************************************************************************/
      log_info("Communicating with SOAP server.");
      PerformSOAPCommunication(&context);

      /*************************************************************************
       * В случае успеха посылаем уведомление администратору по email и *
       * обрабатываем выгрузку. *
       *************************************************************************/
      if (context.soapContext != NULL) {
        log_info("Sending emails.");
        SendSMTPMessage(context.smtpContext, context.soapContext);
        soapResult = context.soapContext->soapResult;
        if (context.soapContext->registerZipArchive != NULL) {

          /*************************************************************************
           * Обрабатываем выгрузку файла запрещённых ресурсов РосКомНадзора. *
           *************************************************************************/
          log_info("Parsing RKN blacklist.");
          TZapretBlacklist *blacklist = ProcessRegisterZipArchive(
              context.soapContext->registerZipArchive, context.redirectNSLookup,
              context.timestampFile);
          if (blacklist != NULL) {

            /*************************************************************************
             * Обрабатываем пользовательский файл запрещённых ресурсов. *
             *************************************************************************/
            if (context.customBlacklist != NULL) {
              log_info("Parsing custom blacklist.");
              if (ProcessRegisterCustomBlacklist(context.redirectNSLookup,
                                                 context.customBlacklist,
                                                 blacklist) != true) {
                log_err(ERROR_STR_CUSTOMBL);
              }
            }

            if (context.dnsThreadsContext != NULL ||
                context.httpThreadsContext != NULL) {
              /*************************************************************************
               * Останавливаем потоки фильтрации. *
               *************************************************************************/
              log_info("Stoping filtering threads.");
              StopNetfilterProcessing(context.httpThreadsContext,
                                      context.redirectHTTPCount);
              StopNetfilterProcessing(context.dnsThreadsContext,
                                      context.redirectDNSCount);
            }

            /*************************************************************************
             * Актуализируем хеш-таблицы. *
             *************************************************************************/
            DestroyZapretBlacklist(&context.blacklist);
            context.blacklist = *blacklist;
            memset(blacklist, 0, sizeof(*blacklist));
            free(blacklist);

            if (context.dnsThreadsContext != NULL ||
                context.httpThreadsContext != NULL) {
              /*************************************************************************
               * Запускаем потоки фильтрации. *
               *************************************************************************/
              log_info("Starting filtering threads.");
              StartHTTPNetfilterProcessing(context.httpThreadsContext,
                                           context.redirectHTTPCount,
                                           context.blacklist.httpRules);
              StartDNSNetfilterProcessing(context.dnsThreadsContext,
                                          context.redirectDNSCount,
                                          context.blacklist.dnsNames);
            }

            /*************************************************************************
             * Обновляем списки IPSET. *
             *************************************************************************/
            if (context.redirectIpsetList != NULL) {
              log_info("Updating ipset list.");
              UpdateIpsetList(context.redirectIpsetList,
                              context.blacklist.ipAddresses);
            }
          } else {
            log_err(ERROR_STR_IPSET1);
          }
        }
      }

      /*************************************************************************
       * Очищаем контекст SOAP для следующих итераций. *
       *************************************************************************/
      ClearSOAPContext(context.soapContext);

      /*************************************************************************
       * Вычисляем задержку перед следующей итерацией. *
       *************************************************************************/
      workingPeriod = time(NULL) - workingPeriod;
      if (workingPeriod < context.blacklistCooldownPositive &&
          soapResult == true)
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
    log_info("Going to sleep.");
    if (sleepTime == 0)
      pause();
    else
      sleep(sleepTime);
  }

  log_info("Soft shutdown.");
  exitCode = EXIT_SUCCESS;
error:

  /*************************************************************************
   * Перед выходом очищаем использованные ресурсы.                          *
   *************************************************************************/
  ClearZapretContext(&context);
  xmlCleanupParser();
  Base64Cleanup();
  curl_global_cleanup();
  return exitCode;
}
