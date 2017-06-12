image_name = labs-sortcap

docker_build:
ifndef ECR_HOSTNAME
	$(error ECR_HOSTNAME variable is not set)
endif
	docker build -t ${image_name} --build-arg CACHE_DATE=`date +%Y-%m-%d:%H:%M:%S` .
	docker tag ${image_name}:latest ${ECR_HOSTNAME}/${image_name}:latest

docker_push:
ifndef ECR_HOSTNAME
	$(error ECR_HOSTNAME variable is not set)
endif
	`aws ecr get-login`
	aws ecr describe-repositories --repository-names ${image_name} || aws ecr create-repository --repository-name ${image_name}
	docker push ${ECR_HOSTNAME}/${image_name}:latest

docker_pull:
ifndef ECR_HOSTNAME
	$(error ECR_HOSTNAME variable is not set)
endif
	`aws ecr get-login`
	docker pull ${ECR_HOSTNAME}/${image_name}:latest

