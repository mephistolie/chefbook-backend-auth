package daemon

import (
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/internal/transport/dependencies/service"
	"sync"
	"time"
)

type Daemon struct {
	wg                           *sync.WaitGroup
	profileDeletion              service.ProfileDeletion
	profileDeletionCheckInterval time.Duration
}

func New(profileDeletion service.ProfileDeletion, cfg config.ProfileDeletion) *Daemon {
	return &Daemon{
		wg:                           &sync.WaitGroup{},
		profileDeletion:              profileDeletion,
		profileDeletionCheckInterval: *cfg.CheckInterval,
	}
}

func (d *Daemon) Start() {
	go func() {
		for {
			d.wg.Add(1)
			d.profileDeletion.ExecuteAll()
			d.wg.Done()
			time.Sleep(d.profileDeletionCheckInterval)
		}

	}()
}

func (d *Daemon) Stop() {
	d.wg.Wait()
}
