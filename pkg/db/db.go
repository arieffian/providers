package database

import (
	"context"
	"time"

	_ "github.com/lib/pq" //need to running query: postgres driver
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/plugin/dbresolver"
)

type DbConfig struct {
	WriteDsn string
	ReadDsn  string
}

type dbManager struct {
	dbConfig DbConfig
}

type DbInstance struct {
	Db *gorm.DB
}

func (d *dbManager) CreateDbClient(ctx context.Context) (*DbInstance, error) {
	db, err := gorm.Open(postgres.Open(d.dbConfig.WriteDsn), &gorm.Config{
		TranslateError:         true,
		Logger:                 logger.Default.LogMode(logger.Info),
		SkipDefaultTransaction: true,
	})
	if err != nil {
		return nil, err
	}

	db.Use(
		dbresolver.Register(
			dbresolver.Config{
				Sources: []gorm.Dialector{
					postgres.Open(d.dbConfig.ReadDsn),
				},
				Policy:            dbresolver.RandomPolicy{},
				TraceResolverMode: true,
			},
		).
			SetConnMaxIdleTime(time.Hour).
			SetConnMaxLifetime(24 * time.Hour).
			SetMaxIdleConns(100).
			SetMaxOpenConns(200),
	)

	return &DbInstance{
		Db: db,
	}, err
}

func NewDbManager(dbConfig DbConfig) *dbManager {
	return &dbManager{dbConfig}
}
