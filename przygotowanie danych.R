
# kod do pracy licencjackiej Wykrywanie phishingowych stron internetowych
# ak108507

# wczytanie uzywanych bibliotek
library(tidyverse)
library(ROCR)
library(randomForest)
library(rpart)
library(rpart.plot)
library(adabag)
library(ggthemes)
library(InformationValue)
library(caret)
library(pROC)
library(corrplot)


# wczytanie danych
dane <- read_csv("Phishing_Legitimate_full.csv")

# usuniecie nieopisanych zmiennych i zmiennej przyjmujaca jedna wartosc
dane <- dane %>% 
  select(-c("id", "HttpsInHostname", "SubdomainLevelRT","UrlLengthRT", "PctExtResourceUrlsRT",
            "AbnormalExtFormActionR", "ExtMetaScriptLinkRT", "PctExtNullSelfRedirectHyperlinksRT"))

##############################################
################### EDA ######################
##############################################

# informacje
str(dane)
summary(dane)

# sprawdzenie brakow danych
any(apply(dane, 2, anyNA))

# sprawdzenie duplikatow
any(for(i in 1:ncol(dane)){
  for(j in 1:ncol(dane)){
    all(dane[j,] == dane[i,])
  }
})

# zmienna zalezna
table(as.factor(dane$CLASS_LABEL))

# rozklady zmiennych
eda <- function(data, column_variable, column_class, percentage = FALSE, plot = TRUE){
  zmienna <- column_variable
  klasa <- column_class
  dane_full <- data[, c(zmienna, klasa)]
  dane_join <- data[, c(zmienna)]
  dane <- dane_full
  c <- c(zmienna, klasa)
  l <- nrow(dane_full)
  dane <- dane %>%
    group_by(across(all_of(c))) %>% 
    summarise(Liczba1 = n())
  dane <- inner_join(dane,
                     dane_join %>% 
                       group_by(across(zmienna)) %>%
                       summarise(Liczebność = n()),
                     by = zmienna)
  dane <- dane %>%
    mutate(Odsetek = Liczba1/Liczebność *100,
           Odsetek_Liczebnosci = Liczebność/l *100)
  dane <- dane[dane[,2] == 1,]
  if(plot == TRUE){
    if(percentage == FALSE){
      print(ggplot(dane) +
              geom_bar(aes_string(x = zmienna, y = "Liczebność"), stat = "identity", width = 0.6) +
              geom_line(aes(x=(unname(unlist(unique(dane[,1])))), y = Odsetek*100), col = "red") +
              scale_x_continuous(breaks = c((unname(unlist(unique(dane[,1])))))) +
              scale_y_continuous(sec.axis=sec_axis(~.*0.01,name="Odsetek klasy pozytywnej [%]"), expand = c(0,0)) +
              theme_bw(base_size = 12))
    }else{
      print(ggplot(dane) +
              geom_bar(aes_string(x = zmienna, y = "Odsetek_Liczebnosci"), stat = "identity", width = 0.6) +
              geom_line(aes(x=(unname(unlist(unique(dane[,1])))), y = Odsetek), col = "red") +
              scale_x_continuous(breaks = c((unname(unlist(unique(dane[,1])))))) +
              scale_y_continuous(sec.axis=sec_axis(~.,name="Odsetek klasy pozytywnej [%]"),
                                 name = "Odsetek liczbności [%]", expand = c(0,0), limits = c(0,105)) +
              theme_hc(base_size = 13)) +
        theme(plot.margin = unit(c(3,4,3,4),"cm"))
    }
  }
  return(dane)
}

# rozklad kazdej zmiennej wraz z odsetkiem klasy pozytywnej 
for(i in colnames(dane)[-42]){
  eda(dane, i, "CLASS_LABEL", percentage = TRUE)
}

# iv dla zmiennych kategorycznych
for(i in c("MissingTitle", "IframeOrFrame", "SubmitInfoToEmail", "FrequentDomainNameMismatch",
           "AbnormalFormAction", "ExtFormAction", "RelativeFormAction", "InsecureForms", "ExtFavicon",
           "EmbeddedBrandName", "DomainInPaths", "IpAddress", "RandomString")){
  cat(i, ": ", IV(as.factor(as.vector(dane[[i]])), dane$CLASS_LABEL), "\n")
}

# przykladowe wykresy dla pogrupowanych zmiennych ciaglych/dyskretnych
# zmienna PctNullSelfRedirectHyperlinks
dane_kopia <- dane
zmienna <- dane_kopia$PctNullSelfRedirectHyperlinks
etykiety <- levels(cut(zmienna, c(-0.1,0,0.1,0.6,1)))
zmienna <- as.numeric(cut(zmienna, c(-0.1,0,0.1,0.6,1)))
dane_kopia["PctNullSelfRedirectHyperlinks"] <- zmienna
# zmodyfikowana funkcja eda (do rozkladu), aby uwzgledniala etykiety
eda1 <- function(data, column_variable, column_class, percentage = FALSE, plot = TRUE){
  zmienna <- column_variable
  klasa <- column_class
  dane_full <- data[, c(zmienna, klasa)]
  dane_join <- data[, c(zmienna)]
  dane <- dane_full
  c <- c(zmienna, klasa)
  l <- nrow(dane_full)
  dane <- dane %>%
    group_by(across(all_of(c))) %>% 
    summarise(Liczba1 = n())
  dane <- inner_join(dane,
                     dane_join %>% 
                       group_by(across(zmienna)) %>%
                       summarise(Liczebność = n()),
                     by = zmienna)
  dane <- dane %>%
    mutate(Odsetek = Liczba1/Liczebność *100,
           Odsetek_Liczebnosci = Liczebność/l *100)
  dane <- dane[dane[,2] == 1,]
  if(plot == TRUE){
    if(percentage == FALSE){
      print(ggplot(dane) +
              geom_bar(aes_string(x = zmienna, y = "Liczebność"), stat = "identity", width = 0.6) +
              geom_line(aes(x=(unname(unlist(unique(dane[,1])))), y = Odsetek*100), col = "red") +
              scale_x_continuous(breaks = c((unname(unlist(unique(dane[,1]))))), labels = c("0", "(0,0.1]", "(0.1,0.6]", "(0.6,1]")) +
              scale_y_continuous(sec.axis=sec_axis(~.*0.01,name="Odsetek klasy pozytywnej [%]"), expand = c(0,0)) +
              theme_bw(base_size = 12))
    }else{
      print(ggplot(dane) +
              geom_bar(aes_string(x = zmienna, y = "Odsetek_Liczebnosci"), stat = "identity", width = 0.6) +
              geom_line(aes(x=(unname(unlist(unique(dane[,1])))), y = Odsetek), col = "red") +
              scale_x_continuous(breaks = c((unname(unlist(unique(dane[,1]))))), labels = c("0", "(0,0.1]", "(0.1,0.6]", "(0.6,1]")) +
              scale_y_continuous(sec.axis=sec_axis(~.,name="Odsetek klasy pozytywnej [%]"),
                                 name = "Odsetek liczbności [%]", expand = c(0,0), limits = c(0,105)) +
              theme_hc(base_size = 13)) +
        theme(plot.margin = unit(c(3,4,3,4),"cm"))
    }
  }
  return(dane)
}
dane_wykres1 <- eda1(dane_kopia, "PctNullSelfRedirectHyperlinks", "CLASS_LABEL", plot = TRUE, percentage = TRUE)

# zmienna PctExtHyperlinks
zmienna <- dane_kopia$PctExtHyperlinks
etykiety <- levels(cut(zmienna, c(-0.1,0,0.1,0.3,0.7,1)))
zmienna <- as.numeric(cut(zmienna, c(-0.1,0,0.1,0.3,0.7,1)))
dane_kopia["PctExtHyperlinks"] <- zmienna
# zmodyfikowana funkcja eda (do rozkladu), aby uwzgledniala etykiety
eda2 <- function(data, column_variable, column_class, percentage = FALSE, plot = TRUE){
  zmienna <- column_variable
  klasa <- column_class
  dane_full <- data[, c(zmienna, klasa)]
  dane_join <- data[, c(zmienna)]
  dane <- dane_full
  c <- c(zmienna, klasa)
  l <- nrow(dane_full)
  dane <- dane %>%
    group_by(across(all_of(c))) %>% 
    summarise(Liczba1 = n())
  dane <- inner_join(dane,
                     dane_join %>% 
                       group_by(across(zmienna)) %>%
                       summarise(Liczebność = n()),
                     by = zmienna)
  dane <- dane %>%
    mutate(Odsetek = Liczba1/Liczebność *100,
           Odsetek_Liczebnosci = Liczebność/l *100)
  dane <- dane[dane[,2] == 1,]
  if(plot == TRUE){
    if(percentage == FALSE){
      print(ggplot(dane) +
              geom_bar(aes_string(x = zmienna, y = "Liczebność"), stat = "identity", width = 0.6) +
              geom_line(aes(x=(unname(unlist(unique(dane[,1])))), y = Odsetek*100), col = "red") +
              scale_x_continuous(breaks = c((unname(unlist(unique(dane[,1]))))), labels = c("0", "(0,0.1]", "(0.1,0.3]", "(0.3,0.7]", "(0.7,1]")) +
              scale_y_continuous(sec.axis=sec_axis(~.*0.01,name="Odsetek klasy pozytywnej [%]"), expand = c(0,0)) +
              theme_bw(base_size = 12))
    }else{
      print(ggplot(dane) +
              geom_bar(aes_string(x = zmienna, y = "Odsetek_Liczebnosci"), stat = "identity", width = 0.6) +
              geom_line(aes(x=(unname(unlist(unique(dane[,1])))), y = Odsetek), col = "red") +
              scale_x_continuous(breaks = c((unname(unlist(unique(dane[,1]))))), labels = c("0", "(0,0.1]", "(0.1,0.3]", "(0.3,0.7]", "(0.7,1]")) +
              scale_y_continuous(sec.axis=sec_axis(~.,name="Odsetek klasy pozytywnej [%]"),
                                 name = "Odsetek liczbności [%]", expand = c(0,0), limits = c(0,105)) +
              theme_hc(base_size = 13)) +
        theme(plot.margin = unit(c(3,4,3,4),"cm"))
    }
  }
  return(dane)
}
dane_wykres1 <- eda2(dane_kopia, "PctExtHyperlinks", "CLASS_LABEL", plot = TRUE, percentage = TRUE)

# zmienna PctExtResourceUrl
zmienna <- dane_kopia$PctExtResourceUrls
etykiety <- levels(cut(zmienna, c(-0.1,0,0.2,0.4,0.6,0.9,1)))
zmienna <- as.numeric(cut(zmienna, c(-0.1,0,0.2,0.4,0.6,0.9,1)))
dane_kopia["PctExtResourceUrls"] <- zmienna
# zmodyfikowana funkcja eda (do rozkladu), aby uwzgledniala etykiety
eda3 <- function(data, column_variable, column_class, percentage = FALSE, plot = TRUE){
  zmienna <- column_variable
  klasa <- column_class
  dane_full <- data[, c(zmienna, klasa)]
  dane_join <- data[, c(zmienna)]
  dane <- dane_full
  c <- c(zmienna, klasa)
  l <- nrow(dane_full)
  dane <- dane %>%
    group_by(across(all_of(c))) %>% 
    summarise(Liczba1 = n())
  dane <- inner_join(dane,
                     dane_join %>% 
                       group_by(across(zmienna)) %>%
                       summarise(Liczebność = n()),
                     by = zmienna)
  dane <- dane %>%
    mutate(Odsetek = Liczba1/Liczebność *100,
           Odsetek_Liczebnosci = Liczebność/l *100)
  dane <- dane[dane[,2] == 1,]
  if(plot == TRUE){
    if(percentage == FALSE){
      print(ggplot(dane) +
              geom_bar(aes_string(x = zmienna, y = "Liczebność"), stat = "identity", width = 0.6) +
              geom_line(aes(x=(unname(unlist(unique(dane[,1])))), y = Odsetek*100), col = "red") +
              scale_x_continuous(breaks = c((unname(unlist(unique(dane[,1]))))), labels = c("0", "(0,0.2]", "(0.2,0.4]", "(0.4,0.6]", "(0.6,0.9]", "(0.9,1]")) +
              scale_y_continuous(sec.axis=sec_axis(~.*0.01,name="Odsetek klasy pozytywnej [%]"), expand = c(0,0)) +
              theme_bw(base_size = 12))
    }else{
      print(ggplot(dane) +
              geom_bar(aes_string(x = zmienna, y = "Odsetek_Liczebnosci"), stat = "identity", width = 0.6) +
              geom_line(aes(x=(unname(unlist(unique(dane[,1])))), y = Odsetek), col = "red") +
              scale_x_continuous(breaks = c((unname(unlist(unique(dane[,1]))))), labels = c("0", "(0,0.2]", "(0.2,0.4]", "(0.4,0.6]", "(0.6,0.9]", "(0.9,1]")) +
              scale_y_continuous(sec.axis=sec_axis(~.,name="Odsetek klasy pozytywnej [%]"),
                                 name = "Odsetek liczbności [%]", expand = c(0,0), limits = c(0,105)) +
              theme_hc(base_size = 13)) +
        theme(plot.margin = unit(c(3,4,3,4),"cm"))
    }
  }
  return(dane)
}
dane_wykres1 <- eda3(dane_kopia, "PctExtResourceUrls", "CLASS_LABEL", plot = TRUE, percentage = TRUE)

# wybor zmiennych na podstawie AUC dla kazdej zmiennej
AUC <- matrix(nrow = 1, ncol = 2)
for(i in names(dane)){
  t <- dane[,c(i, "CLASS_LABEL")]
  temp_t <- rpart(CLASS_LABEL ~ ., data = t, method = "class")
  temp_auc <- AUROC(dane$CLASS_LABEL, as.vector(predict(temp_t, newdata = dane)[, 2]))
  AUC <- rbind(AUC, c(as.character(i), temp_auc))
}
AUC <- na.omit(AUC)
AUC <- as.data.frame(AUC)
names(AUC) <- c("Nazwa", "AUC")
AUC %>%
  arrange(desc(AUC))

# sila zmiennych kategorycznych wyznaczona na podstawie statystyki chi-kwadrat
Chi2 <- matrix(nrow = 1, ncol = 2)
for(i in c("MissingTitle", "IframeOrFrame", "SubmitInfoToEmail", "FrequentDomainNameMismatch",
           "AbnormalFormAction", "ExtFormAction", "RelativeFormAction", "InsecureForms", "ExtFavicon",
           "EmbeddedBrandName", "DomainInPaths", "IpAddress", "RandomString")){
  temp_chi2 <- chisq.test(dane[,as.character(i)], dane$CLASS_LABEL, correct = FALSE)
  temp_chi2 <- temp_chi2$statistic
  Chi2 <- rbind(Chi2 ,c(as.character(i), unname(temp_chi2)))
}
Chi2 <- na.omit(Chi2)
Chi2 <- as.data.frame(Chi2)
names(Chi2) <- c("Nazwa", "Chi")
Chi2$Chi <- as.numeric(Chi2$Chi)
Chi2 %>% 
  arrange(desc(Chi))

# korelacje
correlations <- cor(dane[c("PctNullSelfRedirectHyperlinks", "PctExtResourceUrls", "PctExtHyperlinks",
                           "QueryLength", "PathLength", "HostnameLength", "NumNumericChars", "NumAmpersand",
                           "NumQueryComponents", "NumUnderscore", "NumDashInHostname", "NumDash",
                           "UrlLength", "PathLevel", "NumDots", "CLASS_LABEL")], method = "pearson", use = "everything")

corr_selected <- cor(dane[c("PctExtHyperlinks", "PctNullSelfRedirectHyperlinks", "PctExtResourceUrls",
                            "NumNumericChars", "NumDash", "PathLevel", "PathLength", "UrlLength"
                            , "NumDots")], method = "pearson", use = "everything")

corrplot(corr_selected, method="color",  
                   type="upper",
                   addCoef.col = "black",
                   tl.col="black", tl.srt=45,
                   diag=TRUE 
)

##############################################
############ PRZYGOTOWANIE DANYCH ############
##############################################

# usuniecie zmiennych ktore maja AUC < 0.55
dane <- dane %>% 
  select(-c(AUC$Nazwa[AUC$AUC < 0.55]))

dane$CLASS_LABEL <- as.factor(dane$CLASS_LABEL)

# zbior testowy i trening 20%
# warstwowe losowanie
set.seed(999)
train_indices <- createDataPartition(dane$CLASS_LABEL, p = 0.8, list = FALSE)
train <- dane[train_indices, ]
test <- dane[-train_indices, ]



##############################################
############## MODELOWANIE ###################
##############################################

######### DRZEWO KLASYFIKACYJNE ##############

# funkcja na kroswalidacje drzewa

CrossVal_tree <- function(n_folds = 5, param = NULL){
  train_positive <- train[train$CLASS_LABEL == 1,]
  train_negative <- train[train$CLASS_LABEL == 0,]
  folds_index <- list()
  size <- (nrow(train)/2)/n_folds
  evaluations <- matrix(nrow=1, ncol = 6)
  for(i in 0:(n_folds-1)){
    folds_index[[(i+1)]] <- seq(1, (nrow(train)/2),by=1)[(1+i*size):((i+1)*size)]
  }
  for(k in 1:n_folds){
    k_train <- rbind(train_positive[-(folds_index[[k]]),], train_negative[-(folds_index[[k]]),])
    k_test <- rbind(train_positive[folds_index[[k]],], train_negative[folds_index[[k]],])
    temp_tree <- rpart(CLASS_LABEL ~ .,
                       data = k_train,
                       method = "class", control = rpart.control(minbucket = 200, cp = 0.001))
    temp_confusion_matrix <- table(k_test$CLASS_LABEL, predict(temp_tree, new = k_test, type = "class"))
    tp <- temp_confusion_matrix[2,2]
    tn <- temp_confusion_matrix[1,1]
    fp <- temp_confusion_matrix[1,2]
    fn <- temp_confusion_matrix[2,1]
    temp_acc <- (tp + tn)/(tp + tn + fp + fn)
    temp_recall <- tp/(tp + fn)
    temp_preci <- tp/(tp + fp)
    temp_speci <- tn/(tn + fp)
    temp_auc <- performance(prediction(as.vector(predict(temp_tree, newdata = k_test)[, 2]), k_test$CLASS_LABEL), "auc")@y.values[[1]]
    evaluations <- rbind(evaluations, c(k, temp_acc, temp_recall, temp_preci, temp_speci, temp_auc))
  }
  colnames(evaluations) <- c("fold", "acc", "recall", "precision", "speci", "auc")
  evaluations <- evaluations[-1,]
  output <- list("evaltuations" = evaluations,
                 "accuracy" = mean(evaluations[,2]),
                 "recall" = mean(evaluations[,3]),
                 "precision" = mean(evaluations[,4]),
                 "specificity" = mean(evaluations[,5]),
                 "auc" = mean(evaluations[,6]))
                 #"fold_train" = k_train,
                 #"fold_test" = k_test)
  return(output)
}

# przykladowa 5 krotna kroswalidacja drzewa
tree_crossvalidation <- CrossVal_tree(5)

# drzewo nr 1
tree <- rpart(CLASS_LABEL ~ .,
              data = train,
              method = "class", control = rpart.control(minbucket = 200, cp = 0.001))

rpart.plot(tree)
tree$cptable
tree$csplit
plotcp(tree)

# drzewo nr 2
tree2 <- rpart(CLASS_LABEL ~ .,
               data = train,
               method = "class", cp = 0, minbucket = 150)
rpart.plot(tree2)
tree2$cptable
tree2$csplit
plotcp(tree2)

# drzewo przyciete
tree_pruned <- rpart(CLASS_LABEL ~ .,
                     data = train,
                     method = "class",
                     control = rpart.control(cp = 0.011063142))
rpart.plot(tree_pruned)

#################### LAS LOSOWY ##############

# kroswalidacja dla lasu dla liczby losowanych atrybutow na wezle
# i liczby budowanych drzew

CrossVal_rf_mtry_ntree <- function(n_folds = 5, mm = NULL, nn = NULL){
  train_positive <- train[train$CLASS_LABEL == 1,]
  train_negative <- train[train$CLASS_LABEL == 0,]
  folds_index <- list()
  size <- (nrow(train)/2)/n_folds
  evaluations <- matrix(nrow=1, ncol = 6)
  for(i in 0:(n_folds-1)){
    folds_index[[(i+1)]] <- seq(1, (nrow(train)/2),by=1)[(1+i*size):((i+1)*size)]
  }
  for(k in 1:n_folds){
    k_train <- rbind(train_positive[-(folds_index[[k]]),], train_negative[-(folds_index[[k]]),])
    k_test <- rbind(train_positive[folds_index[[k]],], train_negative[folds_index[[k]],])
    k_train$CLASS_LABEL <- as.factor(k_train$CLASS_LABEL)
    temp_rf <- randomForest(CLASS_LABEL ~ .,
                       data = k_train,
                       mtry = mm,
                       ntree = nn)
    temp_confusion_matrix <- table(k_test$CLASS_LABEL, predict(temp_rf, new = k_test, type = "class"))
    tp <- temp_confusion_matrix[2,2]
    tn <- temp_confusion_matrix[1,1]
    fp <- temp_confusion_matrix[1,2]
    fn <- temp_confusion_matrix[2,1]
    temp_acc <- (tp + tn)/(tp + tn + fp + fn)
    temp_recall <- tp/(tp + fn)
    temp_preci <- tp/(tp + fp)
    temp_speci <- tn/(tn + fp)
    temp_auc <- performance(prediction(as.vector(predict(temp_rf, newdata = k_test, type = "prob")[,2]), k_test$CLASS_LABEL), "auc")@y.values[[1]]
    evaluations <- rbind(evaluations, c(k, temp_acc, temp_recall, temp_preci, temp_speci, temp_auc))
  }
  colnames(evaluations) <- c("fold", "acc", "recall", "precision", "speci", "auc")
  evaluations <- evaluations[-1,]
  output <- list("evaltuations" = evaluations,
                 "accuracy" = mean(evaluations[,2]),
                 "recall" = mean(evaluations[,3]),
                 "precision" = mean(evaluations[,4]),
                 "specificity" = mean(evaluations[,5]),
                 "auc" = mean(evaluations[,6]))
                 #"fold_train" = k_train,
                 #"fold_test" = k_test)
  return(output)
}

# przykladowa 5 krotna kroswalidacja dla 500 drzew i 1 losowanego atrybutu
rf_mtry_crossvalidation <- CrossVal_rf_mtry_ntree(5, 1, 500)

# kroswalidacja pozwalajaca ocenic rozne kombinacje parametrow
mtry_stats <- matrix(ncol = 7, nrow = 1)

for(m in 1:19){
  for(n in c(250, 500, 750, 1000, 1250, 1500, 1750, 2000)){
    temp_rf_mtry_cv <- CrossVal_rf_mtry_ntree(5, m, n)
    cat("Mtry", m, "with", n, "trees", "was finished", "\n")
    mtry_stats <- rbind(mtry_stats, c(m, n, temp_rf_mtry_cv$accuracy, temp_rf_mtry_cv$recall, temp_rf_mtry_cv$precision, temp_rf_mtry_cv$specificity, temp_rf_mtry_cv$auc))
  }
}
colnames(mtry_stats) <- c("mtry", "ntree", "acc", "recall", "precision", "speci", "auc")
mtry_stats <- na.omit(mtry_stats)
mtry_stats <- as.data.frame(mtry_stats)
mtry_stats

plot_mtry <- mtry_stats %>% 
  group_by(mtry) %>% 
  summarise(auc_mean = mean(auc),
            accuracy_mean = mean(acc),
            recall_mean = mean(recall),
            precision_mean = mean(precision),
            specificity_mean = mean(speci))

ggplot(data = plot_mtry) +
  geom_line(aes(x = mtry, y = accuracy_mean, color = "Accuracy"), lwd = 0.7) +
  geom_line(aes(x = mtry, y = recall_mean, col = "Recall"), lwd = 0.7) +
  geom_line(aes(x = mtry, y = precision_mean, col = "Precision"), lwd = 0.7) +
  geom_line(aes(x = mtry, y = auc_mean, col = "AUC"), lwd = 0.7) +
  geom_line(aes(x = mtry, y = specificity_mean, col = "Specificity"), lwd = 0.7, linetype = "dashed") +
  scale_y_continuous(expand = c(0,0), limits = c(0.950, 1), name = "Średnia wartość statystyki") +
  scale_x_continuous(name = "Liczba losowanych atrybutów", breaks = c(seq(1,19,by=1))) +
  theme_hc(base_size = 11) +
  scale_color_manual(name = "Statystyka",
                     values = c("AUC" = "#227c9d", "Accuracy" = "#17c3b2", "Recall" = "#fe6d73", "Precision" = "#ffcb77",
                                "Specificity" = "#9381ff"),
                     guide = guide_legend()) +
  theme(legend.position = "right")


plot_ntree <- mtry_stats %>% 
  group_by(ntree) %>% 
  summarise(auc_mean = mean(auc),
            accuracy_mean = mean(acc),
            recall_mean = mean(recall),
            precision_mean = mean(precision),
            specificity_mean = mean(speci))

ggplot() +
  #geom_line(aes(x = plot_ntree$ntree, y = plot_ntree$accuracy_mean, color = "Accuracy"), lwd = 0.7) +
  #geom_line(aes(x = plot_ntree$ntree, y = plot_ntree$recall_mean, col = "Recall"), lwd = 0.7) +
  #geom_line(aes(x = plot_ntree$ntree, y = plot_ntree$precision_mean, col = "Precision"), lwd = 0.7) +
  geom_line(aes(x = plot_ntree$ntree, y = plot_ntree$auc_mean, col = "AUC"), lwd = 0.7) +
  #geom_line(aes(x = plot_ntree$ntree, y = plot_ntree$specificity_mean, col = "Specificity"), lwd = 0.7, linetype = "dashed") +
  scale_y_continuous(expand = c(0,0), limits = c(0.9955, 0.997), name = "Średnia wartość statystyki",
                     breaks = c(seq(0.9955, 0.9970, length.out = 6))) +
  scale_x_continuous(name = "Liczba budowanych drzew", breaks = c(seq(250,2000,by=250))) +
  theme_hc(base_size = 11) +
  scale_color_manual(name = "Statystyka",
                     values = c("AUC" = "#227c9d", "Accuracy" = "#17c3b2", "Recall" = "#fe6d73", "Precision" = "#ffcb77",
                                "Specificity" = "#9381ff"),
                     guide = guide_legend()) +
  theme(legend.position = "right")


plot_mtry3 <- mtry_stats %>% 
  filter(mtry == 3)

ggplot() +
  #geom_line(aes(x = plot_mtry3$ntree, y = plot_mtry3$acc, color = "Accuracy"), lwd = 0.7) +
  #geom_line(aes(x = plot_mtry3$ntree, y = plot_mtry3$recall, col = "Recall"), lwd = 0.7) +
  #geom_line(aes(x = plot_mtry3$ntree, y = plot_mtry3$precision, col = "Precision"), lwd = 0.7) +
  geom_line(aes(x = plot_mtry3$ntree, y = plot_mtry3$auc, col = "AUC"), lwd = 0.7) +
  #geom_line(aes(x = plot_mtry3$ntree, y = plot_mtry3$speci, col = "Specificity"), lwd = 0.7, linetype = "dashed") +
  scale_y_continuous(expand = c(0,0), limits = c(0.996, 1), name = "Średnia wartość statystyki",
                     breaks = c(seq(0.996, 1, length.out = 5))) +
  scale_x_continuous(name = "Liczba budowanych drzew", breaks = c(seq(250,2000,by=250))) +
  theme_hc(base_size = 11) +
  scale_color_manual(name = "Statystyka",
                     values = c("AUC" = "#227c9d", "Accuracy" = "#17c3b2", "Recall" = "#fe6d73", "Precision" = "#ffcb77",
                                "Specificity" = "#9381ff"),
                     guide = guide_legend()) +
  theme(legend.position = "right")

# las losowy nr 1
train$CLASS_LABEL <- as.factor(train$CLASS_LABEL)

rf <- randomForest(CLASS_LABEL ~ .,
                   data = train, mtry = 3, ntree = 250)

# las losowy nr 2
rf2 <- randomForest(CLASS_LABEL ~ .,
                   data = train, mtry = 3, ntree = 500)


# las losowy nr 3
rf3 <- randomForest(CLASS_LABEL ~ .,
                    data = train, mtry = 3, ntree = 1500)

# las losowy nr 4
rf4 <- randomForest(CLASS_LABEL ~ .,
                    data = train, mtry = 3, ntree = 750)

# feature importance plot dla lasu losowego
rf_importance <- as.data.frame(rf$importance)
rf_importance[,2] <- names(rf$importance[,1])
names(rf_importance)[2] <- "Atrybut"
rf_importance <- rf_importance %>% 
  arrange(MeanDecreaseGini)
nazwy <- rf_importance$Atrybut
rf_importance$Atrybut <- factor(rf_importance$Atrybut, levels = nazwy)

ggplot(rf_importance) +
  geom_col(aes(MeanDecreaseGini, Atrybut), fill = "#076fa2", width = 0.6) +
  scale_x_continuous(expand = c(0, 0), limits = c(0,1030)) +
  theme_hc(base_size = 11) 


################### AdaBoost #####################

train <- as.data.frame(train)
test <- as.data.frame(test)
train$CLASS_LABEL <- as.factor(train$CLASS_LABEL)

# kroswalidacja dla adaboost dla parametrow: glebokosci drzewa i liczby drzew

CrossVal_adaboost <- function(n_folds = 5, depth = NULL, ntr = NULL){
  train_positive <- train[train$CLASS_LABEL == 1,]
  train_negative <- train[train$CLASS_LABEL == 0,]
  folds_index <- list()
  size <- (nrow(train)/2)/n_folds
  evaluations <- matrix(nrow=1, ncol = 5)
  for(i in 0:(n_folds-1)){
    folds_index[[(i+1)]] <- seq(1, (nrow(train)/2),by=1)[(1+i*size):((i+1)*size)]
  }
  for(k in 1:n_folds){
    k_train <- rbind(train_positive[-(folds_index[[k]]),], train_negative[-(folds_index[[k]]),])
    k_test <- rbind(train_positive[folds_index[[k]],], train_negative[folds_index[[k]],])
    t_train <- as.data.frame(k_train)
    k_test <- as.data.frame(k_test)
    k_train$CLASS_LABEL <- as.factor(k_train$CLASS_LABEL)
    temp_adaboost <- boosting(CLASS_LABEL ~ .,
                              data = k_train,
                              mfinal = ntr,
                              coeflearn = 'Freund',
                              control = rpart.control(maxdepth = depth,cp = -1),
                              boos = FALSE)
    temp_preds <- predict(temp_adaboost, k_test)
    temp_confusion_matrix <- table(k_test$CLASS_LABEL, as.numeric(temp_preds$class))
    tp <- temp_confusion_matrix[2,2]
    tn <- temp_confusion_matrix[1,1]
    fp <- temp_confusion_matrix[1,2]
    fn <- temp_confusion_matrix[2,1]
    temp_acc <- (tp + tn)/(tp + tn + fp + fn)
    temp_recall <- tp/(tp + fn)
    temp_preci <- tp/(tp + fp)
    temp_speci <- tn/(tn + fp)
    evaluations <- rbind(evaluations, c(k, temp_acc, temp_recall, temp_preci, temp_speci))
  }
  colnames(evaluations) <- c("fold", "acc", "recall", "precision", "speci")
  evaluations <- evaluations[-1,]
  output <- list("evaltuations" = evaluations,
                 "accuracy" = mean(evaluations[,2]),
                 "recall" = mean(evaluations[,3]),
                 "precision" = mean(evaluations[,4]),
                 "specificity" = mean(evaluations[,5]))
  #"fold_train" = k_train,
  #"fold_test" = k_test)
  return(output)
}

# przykladowa kroswalidacja 5 krotna dla adaboost max glebokosc 1 i 10 drzew
adaboost_crossvalidation <- CrossVal_adaboost(5, 1, 10)

# kroswalidacja w celu znalezienia optymalnych wartosci parametrow
adaboost_stats <- matrix(ncol = 6, nrow = 1)
c = 1

for(m in 1:6){
  for(n in c(seq(5,45, by = 5),seq(50,150, by = 10), seq(175, 250, by = 25))){
    temp_ada_stats_cv <- CrossVal_adaboost(5, m, n)
    perc <- round(c/(length(1:6)*length(c(seq(5,45, by = 5),seq(50,150, by = 10), seq(175, 250, by = 25)))),digits = 2)*100
    cat("Depth", m, "with", n, "trees", "was finished", "approx.", paste0(perc, "%"), "done","\n")
    adaboost_stats <- rbind(adaboost_stats, c(m, n, temp_ada_stats_cv$accuracy, temp_ada_stats_cv$recall, temp_ada_stats_cv$precision, temp_ada_stats_cv$specificity))
    c <- c + 1
  }
}
colnames(adaboost_stats) <- c("depth", "ntree", "acc", "recall", "precision", "speci")
adaboost_stats <- na.omit(adaboost_stats)
adaboost_stats <- as.data.frame(adaboost_stats)
adaboost_stats

# kontynuacja kroswalidacji adaboost dla max glebokości 7
ada_depth7_stats <- matrix(ncol = 6, nrow = 1)
c = 1
for(t in c(seq(5,45, by = 5),seq(50,150, by = 10), seq(175, 250, by = 25))){
  temp <- CrossVal_adaboost(5, 7, t)
  perc <- round(c/(length(c(seq(5,45, by = 5),seq(50,150, by = 10), seq(175, 250, by = 25)))),digits = 2)*100
  cat("Depth", 7, "with", t, "trees", "was finished", "approx.", paste0(perc, "%"), "done","\n")
  ada_depth7_stats <- rbind(ada_depth7_stats, c(7, t, temp$accuracy, temp$recall, temp$precision, temp$specificity))
  c <- c + 1
}
colnames(ada_depth7_stats) <- c("depth", "ntree", "acc", "recall", "precision", "speci")
ada_depth7_stats <- as.data.frame(na.omit(ada_depth7_stats))
ada_depth7_stats

# kontynuacja kroswalidacji adaboost dla max glebokosci 8
ada_depth8_stats <- matrix(ncol = 6, nrow = 1)
c = 1
for(t in c(seq(5,45, by = 5),seq(50,150, by = 10), seq(175, 250, by = 25))){
  temp <- CrossVal_adaboost(5, 8, t)
  perc <- round(c/(length(c(seq(5,45, by = 5),seq(50,150, by = 10), seq(175, 250, by = 25)))),digits = 2)*100
  cat("Depth", 8, "with", t, "trees", "was finished", "approx.", paste0(perc, "%"), "done","\n")
  ada_depth8_stats <- rbind(ada_depth8_stats, c(7, t, temp$accuracy, temp$recall, temp$precision, temp$specificity))
  c <- c + 1
}
colnames(ada_depth8_stats) <- c("depth", "ntree", "acc", "recall", "precision", "speci")
ada_depth8_stats <- as.data.frame(na.omit(ada_depth8_stats))
ada_depth8_stats$depth <- rep(8, times = length(c(seq(5,45, by = 5),seq(50,150, by = 10), seq(175, 250, by = 25))))
ada_depth8_stats

# wykresy dla adaboost

ada_full_stats <- rbind(adaboost_stats, ada_depth7_stats)
ada_full_stats <- rbind(ada_full_stats, ada_depth8_stats)

plot_ada_depth_means <- ada_full_stats %>% 
  group_by(depth) %>% 
  summarise(accuracy_mean = mean(acc),
            recall_mean = mean(recall),
            precision_mean = mean(precision),
            specificity_mean = mean(speci))



ggplot(data = plot_ada_depth_means) +
  geom_line(aes(x = depth, y = accuracy_mean, color = "Accuracy"), lwd = 0.7) +
  geom_line(aes(x = depth, y = recall_mean, col = "Recall"), lwd = 0.7) +
  geom_line(aes(x = depth, y = precision_mean, col = "Precision"), lwd = 0.7) +
  geom_line(aes(x = depth, y = specificity_mean, col = "Specificity"), lwd = 0.7, linetype = "dashed") +
  scale_y_continuous(expand = c(0,0), limits = c(0.95, 1), name = "Średnia wartość statystyki") +
  scale_x_continuous(name = "Głębokość budowanych drzew", breaks = c(seq(1,8,by=1))) +
  theme_hc(base_size = 11) +
  scale_color_manual(name = "Statystyka",
                     values = c("Accuracy" = "#17c3b2", "Recall" = "#fe6d73", "Precision" = "#ffcb77",
                                "Specificity" = "#9381ff"),
                     guide = guide_legend()) +
  theme(legend.position = "right")

plot_ada_depth_6 <- ada_full_stats %>% 
  filter(depth == 6)

ggplot() +
  geom_line(aes(x = plot_ada_depth_6$ntree, y = plot_ada_depth_6$acc, color = "Accuracy"), lwd = 0.7) +
  geom_line(aes(x = plot_ada_depth_6$ntree, y = plot_ada_depth_6$recall, col = "Recall"), lwd = 0.7) +
  geom_line(aes(x = plot_ada_depth_6$ntree, y = plot_ada_depth_6$precision, col = "Precision"), lwd = 0.7) +
  geom_line(aes(x = plot_ada_depth_6$ntree, y = plot_ada_depth_6$speci, col = "Specificity"), lwd = 0.7, linetype = "dashed") +
  scale_y_continuous(expand = c(0,0), limits = c(0.95, 1), name = "Średnia wartość statystyki",
                     breaks = c(seq(0.95, 1, length.out = 5))) +
  scale_x_continuous(name = "Liczba budowanych drzew") +
  theme_hc(base_size = 11) +
  scale_color_manual(name = "Statystyka",
                     values = c("Accuracy" = "#17c3b2", "Recall" = "#fe6d73", "Precision" = "#ffcb77",
                                "Specificity" = "#9381ff"),
                     guide = guide_legend()) +
  theme(legend.position = "right")

# adaboost nr 1
ada <- boosting(CLASS_LABEL ~ ., data = train, mfinal = 130,
                coeflearn = 'Freund', control = rpart.control(maxdepth = 6, cp = 0.001),
                boos = FALSE)
preds <- predict(ada, test)

# adaboost nr 2
ada2 <- boosting(CLASS_LABEL ~ ., data = train, mfinal = 130,
                 coeflearn = 'Freund', control = rpart.control(maxdepth = 6,cp = -1), boos = FALSE)
preds2 <- predict(ada2, test)

# adaboost nr 3
ada3 <- boosting(CLASS_LABEL ~ ., data = train, mfinal = 130,
                 coeflearn = 'Freund', control = rpart.control(maxdepth = 10,cp = -1), boos = FALSE)
preds3 <- predict(ada3, test)

# adaboost nr 4
ada4 <- boosting(CLASS_LABEL ~ ., data = train, mfinal = 200,
                 coeflearn = 'Freund', control = rpart.control(maxdepth = 30), boos = FALSE)
preds4 <- predict(ada4, test)

# feature importance plot dla adaboost
ada_importance <- as.data.frame(ada$importance)
ada_importance[,2] <- names(ada$importance)
names(ada_importance) <- c("MeanDecreaseGini","Atrybut")
ada_importance <- ada_importance %>% 
  arrange(MeanDecreaseGini)
nazwy <- ada_importance$Atrybut
ada_importance$Atrybut <- factor(ada_importance$Atrybut, levels = nazwy)

ggplot(ada_importance) +
  geom_col(aes(MeanDecreaseGini, Atrybut), fill = "#076fa2", width = 0.6) +
  scale_x_continuous(expand = c(0, 0)) +
  theme_hc(base_size = 11) 

# oceny na podstawie macierzy bledow
CM <- list()
CM[["tree"]] <- table(test$CLASS_LABEL, predict(tree, new = test, type = "class"))
CM[["tree2"]] <- table(test$CLASS_LABEL, predict(tree2, new = test, type = "class"))
CM[["tree_pruned"]] <- table(test$CLASS_LABEL, predict(tree_pruned, new = test, type = "class"))
CM[["rf"]] <- table(test$CLASS_LABEL, ifelse(as.vector(predict(rf, newdata = test, type = "class")) > 0.5, 1, 0))
CM[["rf2"]] <- table(test$CLASS_LABEL, ifelse(as.vector(predict(rf2, newdata = test, type = "class")) > 0.5, 1, 0))
CM[["rf3"]] <- table(test$CLASS_LABEL, ifelse(as.vector(predict(rf3, newdata = test, type = "class")) > 0.5, 1, 0))
CM[["rf4"]] <- table(test$CLASS_LABEL, ifelse(as.vector(predict(rf4, newdata = test, type = "class")) > 0.5, 1, 0))
CM[["ada"]] <- table(test$CLASS_LABEL, as.numeric(preds$class))
CM[["ada2"]] <- table(test$CLASS_LABEL, as.numeric(preds2$class))
CM[["ada3"]] <- table(test$CLASS_LABEL, as.numeric(preds3$class))
CM[["ada4"]] <- table(test$CLASS_LABEL, as.numeric(preds4$class))


#CM[["xgb"]] <- table(test$CLASS_LABEL, ifelse(as.vector(predict(xgb, as.matrix(test[,-43]))) > 0.5, 1, 0))
#CM[["xgb_alt"]] <- table(test$CLASS_LABEL, ifelse(as.vector(predict(xgb_alt, as.matrix(test[,-43]))) > 0.5, 1, 0))
#CM[["siec"]] <- table(test$CLASS_LABEL, preds)
#CM[["nn2"]] <- table(test$CLASS_LABEL, ifelse(predict(nn2, new = test) > 0.5, 1,0))

EvaluateModel <- function(classif_mx){
  true_positive <- classif_mx[2, 2]
  true_negative <- classif_mx[1, 1]
  false_positive <- classif_mx[1, 2]
  false_negative <- classif_mx[2, 1]
  condition_positive <- sum(classif_mx[2 , ])
  condition_negative <- sum(classif_mx[1 , ])
  predicted_positive <- sum(classif_mx[, 2])
  predicted_negative <- sum(classif_mx[, 1])
  accuracy <- (true_positive + true_negative) / sum(classif_mx)
  MER <- 1 - accuracy
  precision <- true_positive / predicted_positive
  recall <- true_positive / condition_positive
  specificity <- true_negative / condition_negative
  F1 <- (2 * precision * recall) / (precision + recall)
  return(list(accuracy = accuracy, 
              MER = MER,
              precision = precision,
              recall = recall,
              specificity = specificity,
              F1 = F1))
}

# ocena modelu na podstawie statystyk
sapply(CM, EvaluateModel)

preds_prob <- list()
preds_prob[["tree"]] <- as.vector(predict(tree, newdata = test)[, 2])
preds_prob[["rf"]] <- as.vector(predict(rf, newdata = test, type = "prob")[, 2])

plot(performance(prediction(preds_prob[["tree"]], test$CLASS_LABEL), "tpr", "fpr"), xlab = "False Positive Rate",
     ylab = "True Positive Rate") 
(performance(prediction(preds_prob[["tree"]], test$CLASS_LABEL), "auc")@y.values[[1]])

plot(performance(prediction(preds_prob[["rf"]], test$CLASS_LABEL), "tpr", "fpr"), xlab = "False Positive Rate",
     ylab = "True Positive Rate") 
(performance(prediction(preds_prob[["rf"]], test$CLASS_LABEL), "auc")@y.values[[1]])

plot(performance(prediction(preds_prob[["tree"]], test$CLASS_LABEL), "tpr", "fpr"), lwd = 2, colorize = F, col = "black", add = FALSE, xlab = "False Positive Rate",
     ylab = "True Positive Rate") 
plot(performance(prediction(preds_prob[["rf"]], test$CLASS_LABEL), "tpr", "fpr"), lwd = 2, colorize = F, col = "red", add = TRUE, xlab = "False Positive Rate",
     ylab = "True Positive Rate") 

# lift
plot(performance(prediction(preds_prob[["tree"]], test$CLASS_LABEL), "lift", "rpp"))
plot(performance(prediction(preds_prob[["rf"]], test$CLASS_LABEL), "lift", "rpp"))

plot(performance(prediction(preds_prob[["rf"]], test$CLASS_LABEL), "lift", "rpp"), lwd = 2, colorize = F, col = "red", add = FALSE, xlab = "Skumulowany odsetek obserwacji",
     ylab = "Wartość Lift") 
plot(performance(prediction(preds_prob[["tree"]], test$CLASS_LABEL), "lift", "rpp"), lwd = 2, colorize = F, col = "black", add = TRUE, xlab = "Skumulowany odsetek obserwacji",
     ylab = "Wartość Lift") 


# feature importance dla randomforest z MLlib
nazwy_zmiennych <- colnames(dane)[-20]
fi <- c(0.0319, 0.0337, 0.008, 0.0929, 0.0171, 0.0036, 0.0389, 0.0006, 0.0095, 0.0114, 0.0156, 0.0257, 0.2547, 0.0993, 0.0516, 0.0893, 0.1478, 0.0546, 0.0137)
fi_rf <- as.data.frame(cbind(nazwy_zmiennych, fi))
fi_rf$fi <- as.numeric(fi_rf$fi)
colnames(fi_rf) <- c("Atrybut","MeanDecreaseGini")
fi_rf <- fi_rf %>% 
  arrange(MeanDecreaseGini)
nazwy <- fi_rf$Atrybut
fi_rf$Atrybut <- factor(fi_rf$Atrybut, levels = nazwy)

ggplot(fi_rf) +
  geom_col(aes(MeanDecreaseGini, Atrybut), fill = "#076fa2", width = 0.6) +
  scale_x_continuous(expand = c(0, 0)) +
  theme_hc(base_size = 11) 

# testy innych modeli
# xgboost
# trainxgb <- xgb.DMatrix(data = as.matrix(train[,-43]), label=as.matrix(train[,43]))
# testxgb <- xgb.DMatrix(data = as.matrix(test[,-43]), label=as.matrix(test[,43]))


# xgb <- xgb.train(data = trainxgb,
#                 nrounds = 4000,
#                watchlist = list(train = trainxgb, test = testxgb),
#               params = list(objective = "binary:logistic",
#                            eta = 0.05,
#                           gamma = 0.005),
#            early_stopping_rounds = 50)

# xgboost alt
# xgb_alt <- xgb.train(data = trainxgb,
#                     nrounds = 10000,
#                     watchlist = list(train = trainxgb, test = testxgb),
#                     params = list(objective = "binary:logistic",
#                                   eta = 0.1,
#                                   gamma = 0.001,
#                                  max_depth = 6,
#                                  subsample = 0.8),
#                     early_stopping_rounds = 100,
#                     print_every_n = 100)


