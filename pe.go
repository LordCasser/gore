// This file is part of GoRE.
//
// Copyright (C) 2019-2021 GoRE Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package gore

import (
	"debug/gosym"
	"debug/pe"
	"encoding/binary"
	"fmt"
)

func openPE(fp string) (*peFile, error) {
	f, err := pe.Open(fp)
	if err != nil {
		return nil, err
	}
	return &peFile{file: f}, nil
}

type peFile struct {
	file        *pe.File
	pclntabAddr uint64
	imageBase   uint64
}

func (p *peFile) getPCLNTab() (*gosym.Table, error) {
	addr, pclndat, err := searchFileForPCLNTab(p.file)
	if err != nil {
		return nil, err
	}
	pcln := gosym.NewLineTable(pclndat, uint64(p.file.Section(".text").VirtualAddress))
	p.pclntabAddr = uint64(addr) + p.imageBase
	TypeStringOffsets.PCLnTab = p.pclntabAddr
	return gosym.NewTable(make([]byte, 0), pcln)
}

func (p *peFile) Close() error {
	return p.file.Close()
}

func (p *peFile) getRData() ([]byte, error) {
	section := p.file.Section(".rdata")
	if section == nil {
		return nil, ErrSectionDoesNotExist
	}
	return section.Data()
}

func (p *peFile) getCodeSection() ([]byte, error) {
	section := p.file.Section(".text")
	if section == nil {
		return nil, ErrSectionDoesNotExist
	}
	return section.Data()
}

func (p *peFile) moduledataSection() string {
	return ".data"
}

func (p *peFile) getPCLNTABData() (uint64, []byte, error) {
	b, d, e := searchFileForPCLNTab(p.file)
	return p.imageBase + uint64(b), d, e
}

func (p *peFile) getSectionDataFromOffset(off uint64) (uint64, []byte, error) {
	for _, section := range p.file.Sections {
		if section.Offset == 0 {
			// Only exist in memory
			continue
		}

		if p.imageBase+uint64(section.VirtualAddress) <= off && off < p.imageBase+uint64(section.VirtualAddress+section.Size) {
			data, err := section.Data()
			return p.imageBase + uint64(section.VirtualAddress), data, err
		}
	}
	return 0, nil, ErrSectionDoesNotExist
}

func (p *peFile) getFva(off uint64) (uint64, error) {
	for _, section := range p.file.Sections {
		if p.imageBase+uint64(section.VirtualAddress) <= off && off < p.imageBase+uint64(section.VirtualAddress+section.Size) {
			// rva-base-rdata+rdata_raw_offset
			return off - uint64(section.VirtualAddress) - p.imageBase + uint64(section.Offset), nil
		}
	}
	return 0, ErrSectionDoesNotExist
}

func (p *peFile) getSectionData(name string) (uint64, []byte, error) {
	section := p.file.Section(name)
	if section == nil {
		return 0, nil, ErrSectionDoesNotExist
	}
	data, err := section.Data()
	return p.imageBase + uint64(section.VirtualAddress), data, err
}

func (p *peFile) getFileInfo() *FileInfo {
	fi := &FileInfo{ByteOrder: binary.LittleEndian, OS: "windows"}
	if p.file.Machine == pe.IMAGE_FILE_MACHINE_I386 {
		fi.WordSize = intSize32
		optHdr := p.file.OptionalHeader.(*pe.OptionalHeader32)
		p.imageBase = uint64(optHdr.ImageBase)
		fi.Arch = Arch386
	} else {
		fi.WordSize = intSize64
		optHdr := p.file.OptionalHeader.(*pe.OptionalHeader64)
		p.imageBase = optHdr.ImageBase
		fi.Arch = ArchAMD64
	}
	return fi
}

func (p *peFile) getBuildID() (string, error) {
	data, err := p.getCodeSection()
	if err != nil {
		return "", fmt.Errorf("failed to get code section: %w", err)
	}
	return parseBuildIDFromRaw(data)
}
